package mutation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	diffv1 "github.com/codethor0/axiom-api-scanner/internal/diff/v1"
	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/executil"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/mutate"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

// Store is persistence and findings for mutation runs.
type Store interface {
	GetScan(ctx context.Context, id string) (engine.Scan, error)
	ListScanEndpoints(ctx context.Context, scanID string, filter storage.EndpointListFilter) ([]engine.ScanEndpoint, error)
	GetLatestExecution(ctx context.Context, scanID, scanEndpointID string, phase engine.ExecutionPhase) (engine.ExecutionRecord, error)
	GetMutationByCandidate(ctx context.Context, scanID, scanEndpointID, ruleID, candidateKey string) (engine.ExecutionRecord, error)
	InsertExecutionRecord(ctx context.Context, rec engine.ExecutionRecord) (string, error)
	UpdateMutationState(ctx context.Context, scanID string, st storage.MutationState) error
	GetByEvidenceTuple(ctx context.Context, scanID, ruleID, scanEndpointID, baselineExecutionID, mutatedExecutionID string) (findings.Finding, error)
	CreateFinding(ctx context.Context, in storage.CreateFindingInput) (findings.Finding, error)
}

// Runner executes sequential mutation HTTP requests and may create findings.
type Runner struct {
	HTTP    *http.Client
	Store   Store
	MaxBody int64
}

// NewRunner returns a runner with conservative defaults.
func NewRunner(s Store) *Runner {
	c := &http.Client{
		Timeout: 45 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			if via[0].URL.Scheme != req.URL.Scheme || via[0].URL.Host != req.URL.Host {
				return fmt.Errorf("cross-origin redirect rejected")
			}
			return nil
		},
	}
	return &Runner{HTTP: c, Store: s, MaxBody: 2 << 20}
}

// Result is the machine-readable outcome of a mutation pass.
type Result struct {
	Status               string   `json:"status"`
	Error                string   `json:"error,omitempty"`
	CandidatesTotal      int      `json:"candidates_total"`
	CandidatesExecuted   int      `json:"candidates_executed"`
	CandidatesSkipped    int      `json:"candidates_skipped"`
	MutatedExecutionIDs  []string `json:"mutated_execution_ids"`
	FindingIDs           []string `json:"finding_ids"`
	Warnings             []string `json:"warnings,omitempty"`
}

// Run executes mutations for all work items built from loaded rules (caller supplies rule set via work list builder externally).
func (r *Runner) Run(ctx context.Context, scanID string, work []WorkItem) (Result, error) {
	if r.MaxBody <= 0 {
		r.MaxBody = 2 << 20
	}
	scan, err := r.Store.GetScan(ctx, scanID)
	if err != nil {
		return Result{}, err
	}
	baseStr := strings.TrimSpace(scan.BaseURL)
	if baseStr == "" {
		return Result{Status: "failed", Error: "base_url_required"}, errors.New("base_url_required")
	}
	if scan.BaselineRunStatus != "succeeded" {
		out := Result{Status: "failed", Error: "baseline_must_succeed_first"}
		_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
			Status: "failed", Error: "baseline_must_succeed_first", Total: len(work), Done: 0,
		})
		return out, errors.New("baseline_must_succeed_first")
	}

	total := len(work)
	if total == 0 {
		_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
			Status: "succeeded", Error: "", Total: 0, Done: 0,
		})
		return Result{Status: "succeeded", CandidatesTotal: 0}, nil
	}

	_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
		Status: "in_progress", Total: total, Done: 0,
	})

	var mutIDs []string
	var findIDs []string
	var warns []string
	executed := 0
	skipped := 0

	for _, item := range work {
		select {
		case <-ctx.Done():
			_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
				Status: "failed", Error: ctx.Err().Error(), Total: total, Done: executed,
			})
			return Result{
				Status:              "failed",
				Error:               ctx.Err().Error(),
				CandidatesTotal:     total,
				CandidatesExecuted:  executed,
				CandidatesSkipped:   skipped,
				MutatedExecutionIDs: mutIDs,
				FindingIDs:          findIDs,
				Warnings:            warns,
			}, ctx.Err()
		default:
		}

		ep := item.Endpoint
		candKey := mutate.DedupeKey(item.Candidate)
		baseline, berr := r.Store.GetLatestExecution(ctx, scanID, ep.ID, engine.PhaseBaseline)
		if berr != nil {
			skipped++
			warns = append(warns, fmt.Sprintf("no_baseline:%s", ep.ID))
			continue
		}

		var mutRec engine.ExecutionRecord
		var mutID string
		if prev, perr := r.Store.GetMutationByCandidate(ctx, scanID, ep.ID, item.Candidate.RuleID, candKey); perr == nil {
			mutRec = prev
			mutID = prev.ID
			mutIDs = append(mutIDs, mutID)
			executed++
		} else {
			built, err := BuildRequest(baseStr, ep, item.Rule, item.Candidate)
			if err != nil {
				skipped++
				warns = append(warns, fmt.Sprintf("build_failed:%s:%v", item.Candidate.RuleID, err))
				continue
			}

			if !executil.HasPrefixURL(baseStr, built.URL) {
				skipped++
				warns = append(warns, fmt.Sprintf("out_of_scope:%s", ep.ID))
				continue
			}

			method := built.Method
			if method != http.MethodGet && method != http.MethodPost {
				skipped++
				warns = append(warns, fmt.Sprintf("method_not_supported:%s", method))
				continue
			}

			var bodyReader io.Reader
			if built.Body != "" {
				bodyReader = strings.NewReader(built.Body)
			}
			req, err := http.NewRequestWithContext(ctx, method, built.URL, bodyReader)
			if err != nil {
				skipped++
				continue
			}
			for k, v := range scan.AuthHeaders {
				req.Header.Set(k, v)
			}
			for k, v := range built.ExtraHeader {
				req.Header.Set(k, v)
			}
			req.Header.Set("User-Agent", "Axiom-Mutation/1")
			if built.Body != "" {
				req.Header.Set("Content-Type", "application/json")
			}

			start := time.Now()
			resp, err := r.HTTP.Do(req)
			dur := time.Since(start).Milliseconds()
			status := 0
			respHeaders := map[string]string{}
			respBody := ""
			respCT := ""
			if err != nil {
				warns = append(warns, fmt.Sprintf("http_error:%s:%v", ep.ID, err))
			} else {
				func() {
					defer func() { _ = resp.Body.Close() }()
					status = resp.StatusCode
					respCT = resp.Header.Get("Content-Type")
					respHeaders = executil.RedactSensitiveHeaders(executil.FilterHeaders(resp.Header))
					lim := io.LimitReader(resp.Body, r.MaxBody)
					b, _ := io.ReadAll(lim)
					respBody = executil.NormalizeResponseBody(respCT, b)
				}()
			}

			mutRec = engine.ExecutionRecord{
				ScanID:              scanID,
				ScanEndpointID:      ep.ID,
				Phase:               engine.PhaseMutated,
				RuleID:              item.Candidate.RuleID,
				CandidateKey:        candKey,
				RequestMethod:       method,
				RequestURL:          built.URL,
				RequestHeaders:      executil.RedactSensitiveHeaders(executil.FilterHeaders(req.Header)),
				RequestBody:         built.Body,
				ResponseStatus:      status,
				ResponseHeaders:     respHeaders,
				ResponseBody:        respBody,
				ResponseContentType: respCT,
				DurationMs:          dur,
			}
			var ierr error
			mutID, ierr = r.Store.InsertExecutionRecord(ctx, mutRec)
			if ierr != nil {
				_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
					Status: "failed", Error: ierr.Error(), Total: total, Done: executed,
				})
				return Result{
					Status:              "failed",
					Error:               ierr.Error(),
					CandidatesTotal:     total,
					CandidatesExecuted:  executed,
					CandidatesSkipped:   skipped,
					MutatedExecutionIDs: mutIDs,
					FindingIDs:          findIDs,
					Warnings:            warns,
				}, ierr
			}
			mutIDs = append(mutIDs, mutID)
			mutRec.ID = mutID
			executed++
		}

		diffWrap := diffv1.EvaluateRuleMatchersWithOutcomes(item.Rule, baseline, mutRec)
		if diffWrap.Incomplete {
			warns = append(warns, fmt.Sprintf("diff_incomplete:%s:%s", item.Candidate.RuleID, strings.Join(diffWrap.Reasons, ";")))
			_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
				Status: "in_progress", Total: total, Done: executed,
			})
			continue
		}
		if diffWrap.Pass {
			diffSummary := strings.Join(diffWrap.Reasons, "; ")
			if diffSummary == "" {
				diffSummary = "all_matchers_passed"
			}
			evidenceComplete := strings.TrimSpace(baseline.ID) != "" && strings.TrimSpace(mutID) != "" &&
				baseline.ResponseStatus > 0 && mutRec.ResponseStatus > 0 && strings.TrimSpace(diffSummary) != ""
			weakNotes := rules.WeakMatcherAssessmentNotes(item.Rule)
			tier, assessNotes := findings.AssessFindingTier(
				findings.Severity(strings.TrimSpace(item.Rule.Severity)),
				item.Rule.Confidence,
				weakNotes,
				evidenceComplete,
			)
			summary := findingOperatorSummary(item.Rule.ID, ep.Method, ep.PathTemplate, item.Candidate.Detail, tier, assessNotes)
			diffPts := append([]string(nil), diffWrap.Reasons...)
			for _, o := range diffWrap.Outcomes {
				if strings.TrimSpace(o.Summary) != "" {
					diffPts = append(diffPts, string(o.Kind)+": "+o.Summary)
				}
			}
			summaryRaw, jerr := findings.MarshalEvidenceSummaryJSON(findings.EvidenceSummaryV1{
				RuleID:                 item.Rule.ID,
				BaselineExecutionID:    baseline.ID,
				MutatedExecutionID:     mutID,
				EndpointMethod:         ep.Method,
				EndpointPathTemplate:   ep.PathTemplate,
				MatcherOutcomes:        matcherOutcomeSummaries(diffWrap.Outcomes),
				DiffPoints:             diffPts,
				AssessmentTier:         tier,
				RuleSeverity:           item.Rule.Severity,
				RuleDeclaredConfidence: item.Rule.Confidence,
				AssessmentNotes:        assessNotes,
			})
			summaryBytes := []byte(summaryRaw)
			if jerr != nil {
				summaryBytes = []byte(`{}`)
			}
			if existingFin, gerr := r.Store.GetByEvidenceTuple(ctx, scanID, item.Rule.ID, ep.ID, baseline.ID, mutID); gerr == nil {
				findIDs = append(findIDs, existingFin.ID)
			} else if !errors.Is(gerr, storage.ErrNotFound) {
				_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
					Status: "failed", Error: gerr.Error(), Total: total, Done: executed,
				})
				return Result{
					Status:              "failed",
					Error:               gerr.Error(),
					CandidatesTotal:     total,
					CandidatesExecuted:  executed,
					CandidatesSkipped:   skipped,
					MutatedExecutionIDs: mutIDs,
					FindingIDs:          findIDs,
					Warnings:            warns,
				}, gerr
			} else {
				fin, ferr := r.Store.CreateFinding(ctx, storage.CreateFindingInput{
					ScanID:                 scanID,
					RuleID:                 item.Rule.ID,
					Category:               item.Rule.Category,
					Severity:               findings.Severity(item.Rule.Severity),
					RuleDeclaredConfidence: strings.ToLower(strings.TrimSpace(item.Rule.Confidence)),
					AssessmentTier:         tier,
					Summary:                summary,
					EvidenceSummary:        summaryBytes,
					ScanEndpointID:         ep.ID,
					BaselineExecutionID:    baseline.ID,
					MutatedExecutionID:     mutID,
					EvidenceURI:            "",
					Evidence: storage.CreateEvidenceInput{
						BaselineRequest: requestSnapshot(baseline),
						MutatedRequest:  requestSnapshot(mutRec),
						BaselineBody:    baseline.ResponseBody,
						MutatedBody:     mutRec.ResponseBody,
						DiffSummary:     diffSummary,
					},
				})
				if ferr != nil {
					if errors.Is(ferr, storage.ErrDuplicateFinding) {
						if refetch, rerr := r.Store.GetByEvidenceTuple(ctx, scanID, item.Rule.ID, ep.ID, baseline.ID, mutID); rerr == nil {
							findIDs = append(findIDs, refetch.ID)
						} else {
							_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
								Status: "failed", Error: ferr.Error(), Total: total, Done: executed,
							})
							return Result{
								Status:              "failed",
								Error:               ferr.Error(),
								CandidatesTotal:     total,
								CandidatesExecuted:  executed,
								CandidatesSkipped:   skipped,
								MutatedExecutionIDs: mutIDs,
								FindingIDs:          findIDs,
								Warnings:            warns,
							}, ferr
						}
					} else {
						_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
							Status: "failed", Error: ferr.Error(), Total: total, Done: executed,
						})
						return Result{
							Status:              "failed",
							Error:               ferr.Error(),
							CandidatesTotal:     total,
							CandidatesExecuted:  executed,
							CandidatesSkipped:   skipped,
							MutatedExecutionIDs: mutIDs,
							FindingIDs:          findIDs,
							Warnings:            warns,
						}, ferr
					}
				} else {
					findIDs = append(findIDs, fin.ID)
				}
			}
		}

		_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
			Status: "in_progress", Total: total, Done: executed,
		})
	}

	finalStatus := "succeeded"
	finalErr := ""
	_ = r.Store.UpdateMutationState(ctx, scanID, storage.MutationState{
		Status: finalStatus, Error: finalErr, Total: total, Done: executed,
	})

	return Result{
		Status:              finalStatus,
		Error:               finalErr,
		CandidatesTotal:     total,
		CandidatesExecuted:  executed,
		CandidatesSkipped:   skipped,
		MutatedExecutionIDs: mutIDs,
		FindingIDs:          findIDs,
		Warnings:            warns,
	}, nil
}

// findingOperatorSummary is the persisted one-line finding text (list + detail). Non-confirmed tiers
// append stable assessment note codes so operators see why a row is not confirmed without opening evidence_summary.
func findingOperatorSummary(ruleID, method, pathTemplate, candidateDetail, tier string, assessNotes []string) string {
	s := fmt.Sprintf("rule %s matched for %s %s (%s)", ruleID, method, pathTemplate, candidateDetail)
	if strings.TrimSpace(tier) == "confirmed" || len(assessNotes) == 0 {
		return s
	}
	return s + "; assessment: " + strings.Join(assessNotes, ", ")
}

func requestSnapshot(rec engine.ExecutionRecord) string {
	m := map[string]any{
		"method": rec.RequestMethod,
		"url":    rec.RequestURL,
	}
	if len(rec.RequestHeaders) > 0 {
		m["headers"] = rec.RequestHeaders
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func matcherOutcomeSummaries(in []diffv1.MatcherOutcome) []findings.MatcherOutcomeSummary {
	out := make([]findings.MatcherOutcomeSummary, len(in))
	for i := range in {
		out[i] = findings.MatcherOutcomeSummary{
			Index:   in[i].Index,
			Kind:    in[i].Kind,
			Passed:  in[i].Passed,
			Summary: in[i].Summary,
		}
	}
	return out
}
