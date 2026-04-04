package api

import (
	"time"

	"github.com/chomechomekitchen/axiom-api-scanner/internal/engine"
)

// ExecutionRead is the operator-oriented JSON shape for a stored HTTP exchange.
type ExecutionRead struct {
	ID             string    `json:"id"`
	ScanID         string    `json:"scan_id"`
	ScanEndpointID string    `json:"scan_endpoint_id,omitempty"`
	Phase          string    `json:"phase"`
	// MutationRuleID is set for phase "mutated" when the execution was driven by a rule candidate; empty for baseline.
	MutationRuleID string `json:"mutation_rule_id,omitempty"`
	Request        ExecutionRequestSnap  `json:"request"`
	Response       ExecutionResponseSnap `json:"response"`
	DurationMs     int64                 `json:"duration_ms"`
	CreatedAt      time.Time             `json:"created_at"`
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

// NewExecutionRead maps a domain execution record into the stable API projection.
func NewExecutionRead(r engine.ExecutionRecord) ExecutionRead {
	return ExecutionRead{
		ID:             r.ID,
		ScanID:         r.ScanID,
		ScanEndpointID: r.ScanEndpointID,
		Phase:          string(r.Phase),
		MutationRuleID: r.RuleID,
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
		DurationMs: r.DurationMs,
		CreatedAt:  r.CreatedAt,
	}
}
