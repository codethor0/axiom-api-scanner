package api

import (
	"net/url"
	"strings"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

const executionURLShortMax = 120

// ExecutionRead is the operator-oriented JSON shape for a stored HTTP exchange.
type ExecutionRead struct {
	ID             string `json:"id"`
	ScanID         string `json:"scan_id"`
	ScanEndpointID string `json:"scan_endpoint_id,omitempty"`
	Phase          string `json:"phase"`
	// ExecutionKind mirrors phase (baseline | mutated) so operators can skim lists without inferring role from other fields.
	ExecutionKind string `json:"execution_kind"`
	// MutationRuleID is set for phase "mutated" when the execution was driven by a rule candidate; empty for baseline.
	MutationRuleID string `json:"mutation_rule_id,omitempty"`
	// CandidateKey identifies the mutation work item for mutated rows (resume/dedup); empty for baseline.
	CandidateKey string                `json:"candidate_key,omitempty"`
	Request      ExecutionRequestSnap  `json:"request"`
	Response     ExecutionResponseSnap `json:"response"`
	// RequestSummary and ResponseSummary are length/header counts derived from the same redacted persisted fields as request/response (no extra body material).
	RequestSummary  ExecutionRequestSummary  `json:"request_summary"`
	ResponseSummary ExecutionResponseSummary `json:"response_summary"`
	DurationMs      int64                    `json:"duration_ms"`
	CreatedAt       time.Time                `json:"created_at"`
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
		DurationMs: r.DurationMs,
		CreatedAt:  r.CreatedAt,
	}
}
