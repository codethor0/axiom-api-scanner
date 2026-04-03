package findings

import (
	"encoding/json"
	"time"
)

// Severity is a coarse impact bucket for a finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Finding is an evidence-backed potential logic flaw.
type Finding struct {
	ID          string    `json:"id"`
	ScanID      string    `json:"scan_id"`
	RuleID      string    `json:"rule_id"`
	Category    string    `json:"category"`
	Severity    Severity  `json:"severity"`
	// Confidence is the assessed tier: confirmed, tentative, or incomplete (see evidence_summary for rule-declared confidence).
	Confidence  string          `json:"confidence"`
	Summary     string          `json:"summary"`
	EvidenceSummary json.RawMessage `json:"evidence_summary,omitempty"`
	EvidenceURI string    `json:"evidence_uri"`
	// ScanEndpointID links to the persisted OpenAPI operation row (optional).
	ScanEndpointID string `json:"scan_endpoint_id,omitempty"`
	// BaselineExecutionID and MutatedExecutionID reference execution_records when present.
	BaselineExecutionID string `json:"baseline_execution_id,omitempty"`
	MutatedExecutionID  string `json:"mutated_execution_id,omitempty"`
	Status              string `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// EvidenceArtifact is persisted proof material for a finding.
type EvidenceArtifact struct {
	ID              string    `json:"id"`
	FindingID       string    `json:"finding_id"`
	BaselineRequest string    `json:"baseline_request"`
	MutatedRequest  string    `json:"mutated_request"`
	BaselineBody    string    `json:"baseline_response_body"`
	MutatedBody     string    `json:"mutated_response_body"`
	DiffSummary     string    `json:"diff_summary"`
	CreatedAt       time.Time `json:"created_at"`
}
