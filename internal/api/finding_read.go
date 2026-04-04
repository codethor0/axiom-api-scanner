package api

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

// MatcherOutcomeLine is a concise matcher row for API inspection (stable subset of persisted evidence summaries).
type MatcherOutcomeLine struct {
	Index  int    `json:"index"`
	Kind   string `json:"kind"`
	Passed bool   `json:"passed"`
}

// FindingEvidenceInspection surfaces evidence_summary content and execution linkage for operators.
type FindingEvidenceInspection struct {
	BaselineExecutionID string               `json:"baseline_execution_id,omitempty"`
	MutatedExecutionID  string               `json:"mutated_execution_id,omitempty"`
	MatcherOutcomes     []MatcherOutcomeLine `json:"matcher_outcomes,omitempty"`
	DiffPointCount      int                  `json:"diff_point_count,omitempty"`
}

// FindingRead is the operator read projection for list and GET finding (same columns as storage; adds evidence_inspection when parsable).
type FindingRead struct {
	ID                     string                     `json:"id"`
	ScanID                 string                     `json:"scan_id"`
	RuleID                 string                     `json:"rule_id"`
	Category               string                     `json:"category"`
	Severity               findings.Severity          `json:"severity"`
	RuleDeclaredConfidence string                     `json:"rule_declared_confidence"`
	AssessmentTier         string                     `json:"assessment_tier"`
	Summary                string                     `json:"summary"`
	EvidenceSummary        json.RawMessage            `json:"evidence_summary,omitempty"`
	EvidenceURI            string                     `json:"evidence_uri"`
	ScanEndpointID         string                     `json:"scan_endpoint_id,omitempty"`
	BaselineExecutionID    string                     `json:"baseline_execution_id,omitempty"`
	MutatedExecutionID     string                     `json:"mutated_execution_id,omitempty"`
	CreatedAt              time.Time                  `json:"created_at"`
	EvidenceInspection     *FindingEvidenceInspection `json:"evidence_inspection,omitempty"`
}

// NewFindingRead maps a persisted finding into the API read model.
func NewFindingRead(f findings.Finding) FindingRead {
	out := FindingRead{
		ID:                     f.ID,
		ScanID:                 f.ScanID,
		RuleID:                 f.RuleID,
		Category:               f.Category,
		Severity:               f.Severity,
		RuleDeclaredConfidence: f.RuleDeclaredConfidence,
		AssessmentTier:         f.AssessmentTier,
		Summary:                f.Summary,
		EvidenceSummary:        f.EvidenceSummary,
		EvidenceURI:            f.EvidenceURI,
		ScanEndpointID:         f.ScanEndpointID,
		BaselineExecutionID:    f.BaselineExecutionID,
		MutatedExecutionID:     f.MutatedExecutionID,
		CreatedAt:              f.CreatedAt,
	}
	if len(f.EvidenceSummary) == 0 {
		out.EvidenceInspection = linkageInspection(f.BaselineExecutionID, f.MutatedExecutionID, nil, 0)
		return out
	}
	var v1 findings.EvidenceSummaryV1
	if err := json.Unmarshal(f.EvidenceSummary, &v1); err != nil {
		out.EvidenceInspection = linkageInspection(f.BaselineExecutionID, f.MutatedExecutionID, nil, 0)
		return out
	}
	mo := make([]MatcherOutcomeLine, 0, len(v1.MatcherOutcomes))
	for _, row := range v1.MatcherOutcomes {
		mo = append(mo, MatcherOutcomeLine{
			Index:  row.Index,
			Kind:   strings.TrimSpace(row.Kind),
			Passed: row.Passed,
		})
	}
	baseID := f.BaselineExecutionID
	if baseID == "" {
		baseID = v1.BaselineExecutionID
	}
	mutID := f.MutatedExecutionID
	if mutID == "" {
		mutID = v1.MutatedExecutionID
	}
	out.EvidenceInspection = linkageInspection(baseID, mutID, mo, len(v1.DiffPoints))
	return out
}

func linkageInspection(baseID, mutID string, outcomes []MatcherOutcomeLine, diffN int) *FindingEvidenceInspection {
	if baseID == "" && mutID == "" && len(outcomes) == 0 && diffN == 0 {
		return nil
	}
	return &FindingEvidenceInspection{
		BaselineExecutionID: baseID,
		MutatedExecutionID:  mutID,
		MatcherOutcomes:     outcomes,
		DiffPointCount:      diffN,
	}
}
