package engine

import "time"

// ScanStatus is the lifecycle state of a scan job.
type ScanStatus string

const (
	ScanQueued    ScanStatus = "queued"
	ScanRunning   ScanStatus = "running"
	ScanPaused    ScanStatus = "paused"
	ScanCanceled  ScanStatus = "canceled"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
)

// Scan represents a single scoped execution against a target API.
type Scan struct {
	ID                   string  `json:"id"`
	Status               ScanStatus `json:"status"`
	RunPhase             ScanRunPhase `json:"run_phase"`
	RunError             string  `json:"run_error,omitempty"`
	TargetLabel          string  `json:"target_label"`
	SafetyMode           string  `json:"safety_mode"`
	AllowFullExecution   bool    `json:"allow_full_execution"`
	BaseURL              string  `json:"base_url"`
	AuthHeaders          map[string]string `json:"auth_headers,omitempty"`
	BaselineRunStatus    string  `json:"baseline_run_status,omitempty"`
	BaselineRunError     string  `json:"baseline_run_error,omitempty"`
	BaselineEndpointsTotal int   `json:"baseline_endpoints_total"`
	BaselineEndpointsDone  int   `json:"baseline_endpoints_done"`
	MutationRunStatus      string  `json:"mutation_run_status,omitempty"`
	MutationRunError       string  `json:"mutation_run_error,omitempty"`
	MutationCandidatesTotal int  `json:"mutation_candidates_total"`
	MutationCandidatesDone  int  `json:"mutation_candidates_done"`
	FindingsCount          int   `json:"findings_count"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// Endpoint describes one operation surfaced by an imported OpenAPI spec.
type Endpoint struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	OperationID string `json:"operation_id,omitempty"`
	Summary     string `json:"summary,omitempty"`
}
