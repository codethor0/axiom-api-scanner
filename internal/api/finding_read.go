package api

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

// MatcherOutcomeLine is a concise matcher row for API inspection (stable subset of persisted evidence summaries).
// Rows are sorted by index ascending on read for deterministic inspection (order in persisted JSON may vary).
type MatcherOutcomeLine struct {
	Index  int    `json:"index"`
	Kind   string `json:"kind"`
	Passed bool   `json:"passed"`
}

// FindingEvidenceInspection surfaces a stable, scan-safe view of matcher/diff facets inside evidence_summary.
// Execution linkage also appears on the parent finding/list row; when present in both places, values match after merge from evidence_summary (see mergedFindingExecutionIDs).
type FindingEvidenceInspection struct {
	BaselineExecutionID string               `json:"baseline_execution_id,omitempty"`
	MutatedExecutionID  string               `json:"mutated_execution_id,omitempty"`
	MatcherOutcomes     []MatcherOutcomeLine `json:"matcher_outcomes,omitempty"`
	DiffPointCount      int                  `json:"diff_point_count,omitempty"`
}

// FindingListItem is the list projection for GET .../findings: ranked triage fields first, linkage and
// evidence_uri, optional evidence_inspection, no raw evidence_summary blob (use GET /v1/findings/{id} for that).
type FindingListItem struct {
	ID                     string                     `json:"id"`
	RuleID                 string                     `json:"rule_id"`
	Severity               findings.Severity          `json:"severity"`
	RuleDeclaredConfidence string                     `json:"rule_declared_confidence"`
	AssessmentTier         string                     `json:"assessment_tier"`
	ScanID                 string                     `json:"scan_id"`
	Category               string                     `json:"category"`
	ScanEndpointID         string                     `json:"scan_endpoint_id,omitempty"`
	BaselineExecutionID    string                     `json:"baseline_execution_id,omitempty"`
	MutatedExecutionID     string                     `json:"mutated_execution_id,omitempty"`
	EvidenceURI            string                     `json:"evidence_uri"`
	Summary                string                     `json:"summary"`
	EvidenceInspection     *FindingEvidenceInspection `json:"evidence_inspection,omitempty"`
	CreatedAt              time.Time                  `json:"created_at"`
}

// FindingRead is the operator read projection for GET /v1/findings/{findingID} (full columns including raw evidence_summary).
//
// Semantic separation (orthogonal fields):
//   - severity: impact bucket for the finding (rule/finding pipeline).
//   - rule_declared_confidence: rule-pack quality signal from authoring (high / medium / low); not post-run proof.
//   - assessment_tier: post-run evidence sufficiency (confirmed / tentative / incomplete) from stored assessment.
//   - summary: one-line operator text (human-written or generated); not structured evidence.
//   - evidence_summary: opaque persisted JSON (schema_version + matcher/diff payload); use evidence_inspection for a stable subset without re-parsing.
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

func mergedFindingExecutionIDs(f findings.Finding) (baselineID, mutatedID string) {
	base := strings.TrimSpace(f.BaselineExecutionID)
	mut := strings.TrimSpace(f.MutatedExecutionID)
	if len(f.EvidenceSummary) == 0 {
		return base, mut
	}
	var v1 findings.EvidenceSummaryV1
	if err := json.Unmarshal(f.EvidenceSummary, &v1); err != nil {
		return base, mut
	}
	if base == "" {
		base = strings.TrimSpace(v1.BaselineExecutionID)
	}
	if mut == "" {
		mut = strings.TrimSpace(v1.MutatedExecutionID)
	}
	return base, mut
}

// parseFindingEvidenceInspection derives matcher/diff cues and execution linkage from the row and JSON summary.
func parseFindingEvidenceInspection(f findings.Finding) *FindingEvidenceInspection {
	baseMerged, mutMerged := mergedFindingExecutionIDs(f)
	if len(f.EvidenceSummary) == 0 {
		return linkageInspection(baseMerged, mutMerged, nil, 0)
	}
	var v1 findings.EvidenceSummaryV1
	if err := json.Unmarshal(f.EvidenceSummary, &v1); err != nil {
		return linkageInspection(baseMerged, mutMerged, nil, 0)
	}
	mo := make([]MatcherOutcomeLine, 0, len(v1.MatcherOutcomes))
	for _, row := range v1.MatcherOutcomes {
		mo = append(mo, MatcherOutcomeLine{
			Index:  row.Index,
			Kind:   strings.TrimSpace(row.Kind),
			Passed: row.Passed,
		})
	}
	sort.Slice(mo, func(i, j int) bool {
		if mo[i].Index != mo[j].Index {
			return mo[i].Index < mo[j].Index
		}
		if mo[i].Kind != mo[j].Kind {
			return mo[i].Kind < mo[j].Kind
		}
		return !mo[i].Passed && mo[j].Passed
	})
	return linkageInspection(baseMerged, mutMerged, mo, len(v1.DiffPoints))
}

func linkageInspection(baseID, mutID string, outcomes []MatcherOutcomeLine, diffN int) *FindingEvidenceInspection {
	baseID = strings.TrimSpace(baseID)
	mutID = strings.TrimSpace(mutID)
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

// NewFindingListItem maps a persisted finding to the list row shape (no evidence_summary JSON).
func NewFindingListItem(f findings.Finding) FindingListItem {
	baseID, mutID := mergedFindingExecutionIDs(f)
	return FindingListItem{
		ID:                     f.ID,
		RuleID:                 f.RuleID,
		Severity:               f.Severity,
		RuleDeclaredConfidence: strings.TrimSpace(f.RuleDeclaredConfidence),
		AssessmentTier:         strings.TrimSpace(f.AssessmentTier),
		ScanID:                 f.ScanID,
		Category:               f.Category,
		ScanEndpointID:         f.ScanEndpointID,
		BaselineExecutionID:    baseID,
		MutatedExecutionID:     mutID,
		EvidenceURI:            f.EvidenceURI,
		Summary:                f.Summary,
		EvidenceInspection:     parseFindingEvidenceInspection(f),
		CreatedAt:              f.CreatedAt,
	}
}

// NewFindingRead maps a persisted finding into the API read model for GET by id.
func NewFindingRead(f findings.Finding) FindingRead {
	baseID, mutID := mergedFindingExecutionIDs(f)
	return FindingRead{
		ID:                     f.ID,
		ScanID:                 f.ScanID,
		RuleID:                 f.RuleID,
		Category:               f.Category,
		Severity:               f.Severity,
		RuleDeclaredConfidence: strings.TrimSpace(f.RuleDeclaredConfidence),
		AssessmentTier:         strings.TrimSpace(f.AssessmentTier),
		Summary:                f.Summary,
		EvidenceSummary:        f.EvidenceSummary,
		EvidenceURI:            f.EvidenceURI,
		ScanEndpointID:         f.ScanEndpointID,
		BaselineExecutionID:    baseID,
		MutatedExecutionID:     mutID,
		CreatedAt:              f.CreatedAt,
		EvidenceInspection:     parseFindingEvidenceInspection(f),
	}
}
