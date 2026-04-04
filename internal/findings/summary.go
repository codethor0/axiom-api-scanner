package findings

import (
	"encoding/json"
	"strings"
)

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
	// RuleSeverity is the rule YAML severity (impact bucket) copied at capture time; same meaning as ImpactSeverity when both are set.
	RuleSeverity string `json:"rule_severity,omitempty"`
	// ImpactSeverity is the preferred explicit name for the same impact bucket as RuleSeverity and as finding.severity (writers populate both).
	ImpactSeverity string `json:"impact_severity,omitempty"`
	// RuleDeclaredConfidence duplicates the column for bundle consumers (same as finding.rule_declared_confidence).
	RuleDeclaredConfidence string `json:"rule_declared_confidence"`
	AssessmentNotes        []string `json:"assessment_notes,omitempty"`
}

// UnmarshalJSON normalizes impact_severity and rule_severity so either key can appear in stored JSON.
func (s *EvidenceSummaryV1) UnmarshalJSON(data []byte) error {
	type alias EvidenceSummaryV1
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*s = EvidenceSummaryV1(a)
	rs := strings.TrimSpace(s.RuleSeverity)
	is := strings.TrimSpace(s.ImpactSeverity)
	if rs == "" && is != "" {
		s.RuleSeverity = is
	}
	if is == "" && rs != "" {
		s.ImpactSeverity = rs
	}
	return nil
}

// MarshalEvidenceSummaryJSON encodes EvidenceSummaryV1 for persistence and API.
func MarshalEvidenceSummaryJSON(s EvidenceSummaryV1) (json.RawMessage, error) {
	s.SchemaVersion = evidenceSummarySchemaVersion
	rs := strings.TrimSpace(s.RuleSeverity)
	is := strings.TrimSpace(s.ImpactSeverity)
	switch {
	case rs != "" && is == "":
		s.ImpactSeverity = rs
	case is != "" && rs == "":
		s.RuleSeverity = is
	case rs != "" && is != "" && rs != is:
		// Prefer explicit rule column path: RuleSeverity wins for bundle consistency.
		s.ImpactSeverity = rs
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
