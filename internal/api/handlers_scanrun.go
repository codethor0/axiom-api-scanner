package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/orchestrator"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/go-chi/chi/v5"
)

// scanRunStatus returns operator-facing scan run phase and counters.
func (h *Handler) scanRunStatus(w http.ResponseWriter, r *http.Request) {
	if h.Scans == nil || h.Endpoints == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "persistence is not configured")
		return
	}
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	scan, err := h.Scans.GetScan(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not load scan")
		return
	}
	endpoints, err := h.Endpoints.ListScanEndpointsForRunStatus(r.Context(), id, storage.EndpointListFilter{})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not list endpoints")
		return
	}
	nEp := len(endpoints)
	secEndpoints := 0
	for _, ep := range endpoints {
		if len(ep.SecuritySchemeHints) > 0 {
			secEndpoints++
		}
	}
	authConfigured := len(scan.AuthHeaders) > 0
	cov := ScanRunCoverage{
		AuthHeadersConfigured:      authConfigured,
		EndpointsDeclaringSecurity: secEndpoints,
	}
	if secEndpoints > 0 && !authConfigured {
		cov.Hints = append(cov.Hints, "imported operations include OpenAPI-declared security ("+strconv.Itoa(secEndpoints)+" operation(s)); scan has no auth_headers, so protected routes may return 401/403 and V1 eligible work may be reduced")
	}
	if authConfigured && secEndpoints > 0 {
		cov.Hints = append(cov.Hints, "auth_headers are present; outbound baseline and mutation requests will include them (sensitive values are never returned by this API)")
	}
	if secEndpoints == 0 && !authConfigured && nEp > 0 {
		cov.Hints = append(cov.Hints, "no operations in the imported spec declare security schemes; auth may still be required by the target for routes not reflected in OpenAPI")
	}

	orchErr := orchestratorErrorOnly(scan)
	runState := ScanRunState{
		Phase:             string(scan.RunPhase),
		OrchestratorError: orchErr,
		BaselineRunStatus: strings.TrimSpace(scan.BaselineRunStatus),
		BaselineRunError:  subBaselineErrorOnly(scan),
		MutationRunStatus: strings.TrimSpace(scan.MutationRunStatus),
		MutationRunError:  subMutationErrorOnly(scan),
	}

	findingsSummary, ferr := buildScanFindingsSummary(r.Context(), h.Findings, id)
	if ferr != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not summarize findings")
		return
	}

	var execTallies []engine.ExecutionRunTally
	if h.Executions != nil {
		var exErr error
		execTallies, exErr = h.Executions.ListExecutionRunTallies(r.Context(), id)
		if exErr != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "could not list execution tallies for run summary")
			return
		}
	}
	mutated := filterMutatedTallies(execTallies)
	protectedCov := buildScanRunProtectedRouteCoverage(endpoints, execTallies, h.Executions != nil)

	var fam ScanRunRuleFamilyCoverage
	switch {
	case h.Executions == nil:
		fam = scanRuleFamilyCoverageExecutionsUnavailable()
	case strings.TrimSpace(h.RulesDir) == "":
		fam = scanRuleFamilyCoverageRulesDirMissing()
	default:
		rulesList, lerr := rules.Loader{}.LoadDir(h.RulesDir)
		if lerr != nil {
			fam = scanRuleFamilyCoverageRulesLoadFailed(lerr)
		} else {
			fam = buildScanRunRuleFamilyCoverage(scan, rulesList, mutated, endpoints, authConfigured)
		}
	}

	diagnostics := buildScanRunDiagnostics(scan, nEp, secEndpoints, authConfigured)
	appendAuthAndRouteDiagnostics(&diagnostics, scan, authConfigured, protectedCov)
	diagnostics.ConsistencyDetail = scanRunConsistencyLines(scan, findingsSummary, h.Findings != nil, len(mutated), fam)

	out := ScanRunStatusResponse{
		Scan: ScanRunScanSummary{
			ID:          scan.ID,
			Status:      string(scan.Status),
			TargetLabel: scan.TargetLabel,
			SafetyMode:  scan.SafetyMode,
		},
		Run: runState,
		Progress: ScanRunProgress{
			EndpointsDiscovered:         nEp,
			BaselineEndpointsTotal:      scan.BaselineEndpointsTotal,
			BaselineExecutionsCompleted: scan.BaselineEndpointsDone,
			MutationCandidatesTotal:     scan.MutationCandidatesTotal,
			MutationExecutionsCompleted: scan.MutationCandidatesDone,
			FindingsCreated:             scan.FindingsCount,
		},
		Summary:                buildScanRunReadSummary(scan, nEp),
		FindingsSummary:        findingsSummary,
		RuleFamilyCoverage:     fam,
		Guidance:               buildScanRunGuidance(scan, nEp, secEndpoints, authConfigured),
		Coverage:               cov,
		ProtectedRouteCoverage: protectedCov,
		Diagnostics:            diagnostics,
		Compatibility: ScanRunCompatibility{
			ScanID:     scan.ID,
			Phase:      string(scan.RunPhase),
			ScanStatus: string(scan.Status),
			LastError:  orchErr,
		},
	}
	writeJSON(w, http.StatusOK, out)
}

func orchestratorErrorOnly(scan engine.Scan) string {
	if scan.RunPhase != engine.PhaseFailed {
		return ""
	}
	return strings.TrimSpace(scan.RunError)
}

// subBaselineErrorOnly returns baseline_run_error only when baseline_run_status is failed (avoids stale text after a later success).
func subBaselineErrorOnly(scan engine.Scan) string {
	if strings.TrimSpace(scan.BaselineRunStatus) != "failed" {
		return ""
	}
	return strings.TrimSpace(scan.BaselineRunError)
}

// subMutationErrorOnly returns mutation_run_error only when mutation_run_status is failed.
func subMutationErrorOnly(scan engine.Scan) string {
	if strings.TrimSpace(scan.MutationRunStatus) != "failed" {
		return ""
	}
	return strings.TrimSpace(scan.MutationRunError)
}

func buildScanRunDiagnostics(scan engine.Scan, endpointsN, secEndpoints int, authConfigured bool) ScanRunDiagnostics {
	d := ScanRunDiagnostics{
		BlockedDetail: make([]ScanRunDiagnosticLine, 0, 2),
		SkippedDetail: make([]ScanRunDiagnosticLine, 0, 2),
	}
	if endpointsN == 0 {
		d.BlockedDetail = append(d.BlockedDetail, ScanRunDiagnosticLine{
			Code:   "no_imported_endpoints",
			Detail: "no scan_endpoints rows; import OpenAPI before baseline or orchestrated run",
		})
	}
	if secEndpoints > 0 && !authConfigured {
		d.BlockedDetail = append(d.BlockedDetail, ScanRunDiagnosticLine{
			Code:   "declared_security_without_auth",
			Detail: strconv.Itoa(secEndpoints) + " imported operation(s) declare security schemes; scan has no auth_headers",
		})
	}
	if endpointsN > 0 && scan.BaselineEndpointsTotal == 0 && scan.RunPhase == engine.PhasePlanned {
		d.SkippedDetail = append(d.SkippedDetail, ScanRunDiagnosticLine{
			Code:   "baseline_not_recorded",
			Detail: "run_phase is planned and baseline_totals on scan row are zero; baseline has not written progress yet",
		})
	}
	if scan.BaselineRunStatus == "succeeded" && scan.MutationRunStatus == "succeeded" && scan.MutationCandidatesTotal == 0 &&
		(scan.RunPhase == engine.PhaseFindingsComplete || scan.RunPhase == engine.PhaseMutationComplete) {
		d.SkippedDetail = append(d.SkippedDetail, ScanRunDiagnosticLine{
			Code:   "zero_mutation_candidates",
			Detail: "mutation pass completed with candidates_total 0 (no eligible rule/work items for imported endpoints in V1)",
		})
	}
	if scan.RunPhase == engine.PhaseFailed {
		d.PhaseFailedNextStep = "POST /v1/scans/{scan_id}/run with body {\"action\":\"resume\"} after addressing orchestrator_error or sub-run errors (sync-only; request blocks until finish)"
		d.ResumeRecommended = true
	}
	return d
}

// scanRunControl starts, resumes, or cancels orchestrated execution (synchronous).
func (h *Handler) scanRunControl(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(chi.URLParam(r, "scanID"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_id", "scan id must be a UUID")
		return
	}
	var req ScanRunControlRequest
	if decErr := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); decErr != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_json", "request body must be JSON")
		return
	}
	action := strings.TrimSpace(strings.ToLower(req.Action))
	switch action {
	case "start", "resume":
		if h.Orchestrator == nil {
			writeAPIError(w, http.StatusServiceUnavailable, "service_unavailable", "scan orchestration is not configured")
			return
		}
		if action == "start" {
			err = h.Orchestrator.Run(r.Context(), id, orchestrator.Options{
				ResumeRetry:        false,
				ForceRerunBaseline: req.ForceRerunBaseline,
			})
		} else {
			err = h.Orchestrator.Run(r.Context(), id, orchestrator.Options{
				ResumeRetry:        true,
				ForceRerunBaseline: req.ForceRerunBaseline,
			})
		}
	case "cancel":
		err = h.cancelOrchestratedScan(r.Context(), id)
	default:
		writeAPIError(w, http.StatusBadRequest, "invalid_scan_run_action", "action must be one of start, resume, cancel")
		return
	}
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		if errors.Is(err, engine.ErrInvalidScanRunPhase) {
			writeAPIError(w, http.StatusConflict, "invalid_run_phase", err.Error())
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "scan_run_failed", err.Error())
		return
	}
	h.scanRunStatus(w, r)
}

func (h *Handler) cancelOrchestratedScan(ctx context.Context, scanID string) error {
	if h.Scans == nil || h.ScanRun == nil {
		return errors.New("persistence not configured")
	}
	if _, err := h.Scans.ApplyControl(ctx, scanID, storage.ScanControlCancel); err != nil && !errors.Is(err, storage.ErrInvalidTransition) {
		return err
	}
	return h.ScanRun.PatchScanRunPhase(ctx, scanID, engine.PhaseCanceled, "")
}
