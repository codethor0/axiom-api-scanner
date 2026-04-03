package engine

import "time"

// ExecutionPhase categorizes stored traffic.
type ExecutionPhase string

const (
	PhaseBaseline ExecutionPhase = "baseline"
	PhaseMutated  ExecutionPhase = "mutated"
)

// ExecutionRecord stores one HTTP exchange for evidence and diffing.
type ExecutionRecord struct {
	ID                  string         `json:"id"`
	ScanID              string         `json:"scan_id"`
	ScanEndpointID      string         `json:"scan_endpoint_id,omitempty"`
	Phase               ExecutionPhase `json:"phase"`
	RuleID              string         `json:"rule_id,omitempty"`
	RequestMethod       string         `json:"request_method"`
	RequestURL          string         `json:"request_url"`
	RequestHeaders      map[string]string `json:"request_headers"`
	RequestBody         string         `json:"request_body"`
	ResponseStatus      int            `json:"response_status"`
	ResponseHeaders     map[string]string `json:"response_headers"`
	ResponseBody        string         `json:"response_body"`
	ResponseContentType string         `json:"response_content_type"`
	DurationMs          int64          `json:"duration_ms"`
	CreatedAt           time.Time      `json:"created_at"`
}
