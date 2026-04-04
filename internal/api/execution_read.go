package api

import (
	"net/url"
	"strings"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

const executionURLShortMax = 120

// ExecutionListItem is the list projection for GET .../executions: phase, rule linkage, summaries, and timing only
// (no request/response body or header maps). GET .../executions/{id} returns the full ExecutionRead.
// mutation_rule_id is empty for baseline rows; list filters accept rule_id or mutation_rule_id (same semantics).
type ExecutionListItem struct {
	ID              string `json:"id"`
	ScanID          string `json:"scan_id"`
	ScanEndpointID  string `json:"scan_endpoint_id,omitempty"`
	Phase           string `json:"phase"`
	ExecutionKind   string `json:"execution_kind"`
	MutationRuleID  string `json:"mutation_rule_id,omitempty"`
	CandidateKey    string `json:"candidate_key,omitempty"`
	RequestSummary  ExecutionRequestSummary  `json:"request_summary"`
	ResponseSummary ExecutionResponseSummary `json:"response_summary"`
	DurationMs      int64                    `json:"duration_ms"`
	CreatedAt       time.Time                `json:"created_at"`
}

// ExecutionRead is the operator-oriented JSON shape for GET /v1/scans/{scanID}/executions/{executionID} (full redacted exchange).
//
// List vs detail: list items expose only request_summary/response_summary; detail adds request/response snapshots (same persisted bytes and header maps subject to redaction).
// Consistency: execution_kind always equals phase for this API. request_summary.method and body/header counts align with request; response_summary.status_code matches response.status_code.
// Rule linkage: mutation_rule_id and candidate_key apply only to mutated phase rows; baseline rows omit them.
// operator_guide clarifies phase role vs mutation linkage and how summaries relate to snapshots (read-path only).
type ExecutionRead struct {
	ID             string `json:"id"`
	ScanID         string `json:"scan_id"`
	ScanEndpointID string `json:"scan_endpoint_id,omitempty"`
	Phase          string `json:"phase"`
	// ExecutionKind mirrors phase (baseline | mutated) for skimming; identical to phase on read (not an alternate classifier).
	ExecutionKind string `json:"execution_kind"`
	// MutationRuleID is set for phase "mutated" when the execution was driven by a rule candidate; empty for baseline.
	MutationRuleID string `json:"mutation_rule_id,omitempty"`
	// CandidateKey identifies the mutation work item for mutated rows (resume/dedup); empty for baseline.
	CandidateKey string                `json:"candidate_key,omitempty"`
	Request      ExecutionRequestSnap  `json:"request"`
	Response     ExecutionResponseSnap `json:"response"`
	// RequestSummary and ResponseSummary are derived from the same persisted fields as request/response (counts, shortened URL, status); they do not add new HTTP material.
	RequestSummary  ExecutionRequestSummary  `json:"request_summary"`
	ResponseSummary ExecutionResponseSummary `json:"response_summary"`
	DurationMs      int64                    `json:"duration_ms"`
	CreatedAt       time.Time                `json:"created_at"`
	OperatorGuide   *ExecutionOperatorGuide  `json:"operator_guide"`
}

// ExecutionOperatorGuide is a stable read-model gloss for operators (no new persisted facts).
type ExecutionOperatorGuide struct {
	PhaseRole                        string `json:"phase_role"`
	LinkageNarration                 string `json:"linkage_narration"`
	SummariesMirrorRedactedSnapshots string `json:"summaries_mirror_redacted_snapshots"`
	// PhaseExecutionKindAlignment and SummariesListDetailParity are stable strings for comparing list vs detail and redundant top-level phase fields.
	PhaseExecutionKindAlignment string `json:"phase_execution_kind_alignment"`
	SummariesListDetailParity     string `json:"summaries_list_detail_parity"`
}

const executionSummariesMirrorNote = "request_summary and response_summary repeat the same persisted request/response fields (method, shortened URL, header/body counts and lengths, status, content-type); they do not add HTTP material beyond those redacted snapshots."

const executionPhaseExecutionKindAlignment = "phase and execution_kind are identical on this API; both label baseline (pre-mutation exchange) versus mutated (post-mutation replay)."

const executionSummariesListDetailParity = "request_summary and response_summary on this object match the GET .../executions list row for the same execution id (same redaction and derivation)."

func executionPhaseRole(phase string) string {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "baseline":
		return "baseline_pre_mutation"
	case "mutated":
		return "mutated_post_mutation"
	default:
		return ""
	}
}

func executionLinkageNarration(r engine.ExecutionRecord) string {
	switch r.Phase {
	case engine.PhaseBaseline:
		return "Baseline capture before mutation; pair with mutated executions for the same scan endpoint (mutation_rule_id / candidate_key on those rows) when diffing for findings."
	case engine.PhaseMutated:
		rule := strings.TrimSpace(r.RuleID)
		ck := strings.TrimSpace(r.CandidateKey)
		switch {
		case rule != "" && ck != "":
			return "Post-mutation replay for mutation rule \"" + rule + "\" (candidate \"" + ck + "\"); compare to the baseline execution for this work item."
		case rule != "":
			return "Post-mutation replay for mutation rule \"" + rule + "\"; compare to the baseline execution for this work item."
		default:
			return "Post-mutation replay; compare to the baseline execution for this work item."
		}
	default:
		return ""
	}
}

func newExecutionOperatorGuide(r engine.ExecutionRecord) *ExecutionOperatorGuide {
	phase := string(r.Phase)
	return &ExecutionOperatorGuide{
		PhaseRole:                        executionPhaseRole(phase),
		LinkageNarration:                 executionLinkageNarration(r),
		SummariesMirrorRedactedSnapshots: executionSummariesMirrorNote,
		PhaseExecutionKindAlignment:      executionPhaseExecutionKindAlignment,
		SummariesListDetailParity:        executionSummariesListDetailParity,
	}
}

// ExecutionRequestSummary is a concise, scanner-safe view for list/detail comparison.
type ExecutionRequestSummary struct {
	Method         string `json:"method"`
	URLShort       string `json:"url_short"`
	HeaderCount    int    `json:"header_count"`
	BodyByteLength int    `json:"body_byte_length"`
}

// ExecutionResponseSummary is a concise view aligned with ExecutionRequestSummary.
type ExecutionResponseSummary struct {
	StatusCode     int    `json:"status_code"`
	ContentType    string `json:"content_type,omitempty"`
	HeaderCount    int    `json:"header_count"`
	BodyByteLength int    `json:"body_byte_length"`
}

// ExecutionRequestSnap is redacted-filtered request metadata as persisted.
type ExecutionRequestSnap struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// ExecutionResponseSnap is normalized response metadata as persisted.
type ExecutionResponseSnap struct {
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

func shortenExecutionURL(raw string, max int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || max <= 3 {
		return raw
	}
	if len(raw) <= max {
		return raw
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		s := u.Scheme + "://" + u.Host + u.EscapedPath()
		if u.RawQuery != "" {
			s += "?" + u.RawQuery
		}
		if len(s) <= max {
			return s
		}
		raw = s
	}
	return raw[:max-3] + "..."
}

// NewExecutionListItem maps a domain execution record into the list projection (summaries only).
func NewExecutionListItem(r engine.ExecutionRecord) ExecutionListItem {
	phase := string(r.Phase)
	return ExecutionListItem{
		ID:             r.ID,
		ScanID:         r.ScanID,
		ScanEndpointID: r.ScanEndpointID,
		Phase:          phase,
		ExecutionKind:  phase,
		MutationRuleID: r.RuleID,
		CandidateKey:   r.CandidateKey,
		RequestSummary: ExecutionRequestSummary{
			Method:         r.RequestMethod,
			URLShort:       shortenExecutionURL(r.RequestURL, executionURLShortMax),
			HeaderCount:    len(r.RequestHeaders),
			BodyByteLength: len(r.RequestBody),
		},
		ResponseSummary: ExecutionResponseSummary{
			StatusCode:     r.ResponseStatus,
			ContentType:    r.ResponseContentType,
			HeaderCount:    len(r.ResponseHeaders),
			BodyByteLength: len(r.ResponseBody),
		},
		DurationMs: r.DurationMs,
		CreatedAt:  r.CreatedAt,
	}
}

// NewExecutionRead maps a domain execution record into the stable API projection.
func NewExecutionRead(r engine.ExecutionRecord) ExecutionRead {
	phase := string(r.Phase)
	return ExecutionRead{
		ID:             r.ID,
		ScanID:         r.ScanID,
		ScanEndpointID: r.ScanEndpointID,
		Phase:          phase,
		ExecutionKind:  phase,
		MutationRuleID: r.RuleID,
		CandidateKey:   r.CandidateKey,
		Request: ExecutionRequestSnap{
			Method:  r.RequestMethod,
			URL:     r.RequestURL,
			Headers: r.RequestHeaders,
			Body:    r.RequestBody,
		},
		Response: ExecutionResponseSnap{
			StatusCode:  r.ResponseStatus,
			Headers:     r.ResponseHeaders,
			Body:        r.ResponseBody,
			ContentType: r.ResponseContentType,
		},
		RequestSummary: ExecutionRequestSummary{
			Method:         r.RequestMethod,
			URLShort:       shortenExecutionURL(r.RequestURL, executionURLShortMax),
			HeaderCount:    len(r.RequestHeaders),
			BodyByteLength: len(r.RequestBody),
		},
		ResponseSummary: ExecutionResponseSummary{
			StatusCode:     r.ResponseStatus,
			ContentType:    r.ResponseContentType,
			HeaderCount:    len(r.ResponseHeaders),
			BodyByteLength: len(r.ResponseBody),
		},
		DurationMs:    r.DurationMs,
		CreatedAt:     r.CreatedAt,
		OperatorGuide: newExecutionOperatorGuide(r),
	}
}
