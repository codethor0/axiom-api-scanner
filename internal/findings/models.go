package findings

import "time"

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
	Confidence  string    `json:"confidence"`
	Summary     string    `json:"summary"`
	EvidenceURI string    `json:"evidence_uri"`
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
