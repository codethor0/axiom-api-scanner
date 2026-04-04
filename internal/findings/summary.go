package findings

import "encoding/json"

const evidenceSummarySchemaVersion = 1

// MatcherOutcomeSummary mirrors diff evaluator rows for persisted evidence summaries.
type MatcherOutcomeSummary struct {
	Index   int    `json:"index"`
	Kind    string `json:"kind"`
	Passed  bool   `json:"passed"`
	Summary string `json:"summary"`
}

// EvidenceSummaryV1 is stored as JSON in findings.evidence_summary (TEXT/JSON).
type EvidenceSummaryV1 struct {
	SchemaVersion int `json:"schema_version"`

	RuleID                string                  `json:"rule_id"`
	BaselineExecutionID  string                  `json:"baseline_execution_id,omitempty"`
	MutatedExecutionID   string                  `json:"mutated_execution_id,omitempty"`
	EndpointMethod       string                  `json:"endpoint_method,omitempty"`
	EndpointPathTemplate string                  `json:"endpoint_path_template,omitempty"`
	MatcherOutcomes      []MatcherOutcomeSummary `json:"matcher_outcomes,omitempty"`
	DiffPoints           []string                `json:"diff_points,omitempty"`

	AssessmentTier string `json:"assessment_tier"`
	RuleSeverity   string `json:"rule_severity"`
	// RuleDeclaredConfidence duplicates the column for bundle consumers (same as finding.rule_declared_confidence).
	RuleDeclaredConfidence string `json:"rule_declared_confidence"`
	AssessmentNotes        []string `json:"assessment_notes,omitempty"`
}

// MarshalEvidenceSummaryJSON encodes EvidenceSummaryV1 for persistence and API.
func MarshalEvidenceSummaryJSON(s EvidenceSummaryV1) (json.RawMessage, error) {
	s.SchemaVersion = evidenceSummarySchemaVersion
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
