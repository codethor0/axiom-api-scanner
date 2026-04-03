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
	ID          string     `json:"id"`
	Status      ScanStatus `json:"status"`
	TargetLabel string     `json:"target_label"`
	SafetyMode  string     `json:"safety_mode"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Endpoint describes one operation surfaced by an imported OpenAPI spec.
type Endpoint struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	OperationID string `json:"operation_id,omitempty"`
	Summary     string `json:"summary,omitempty"`
}
