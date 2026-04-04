package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

func TestMergedFindingExecutionIDs_prefersRowFallsBackToEvidenceSummary(t *testing.T) {
	evSum, err := findings.MarshalEvidenceSummaryJSON(findings.EvidenceSummaryV1{
		BaselineExecutionID: "from-evidence",
		MutatedExecutionID:  "mut-evidence",
	})
	if err != nil {
		t.Fatal(err)
	}
	rowFirst := findings.Finding{
		BaselineExecutionID: "row-b",
		MutatedExecutionID:  "row-m",
		EvidenceSummary:     evSum,
	}
	b, m := mergedFindingExecutionIDs(rowFirst)
	if b != "row-b" || m != "row-m" {
		t.Fatalf("got %q %q", b, m)
	}
	rowEmpty := findings.Finding{
		EvidenceSummary: evSum,
	}
	b, m = mergedFindingExecutionIDs(rowEmpty)
	if b != "from-evidence" || m != "mut-evidence" {
		t.Fatalf("got %q %q", b, m)
	}
}

func TestParseFindingEvidenceInspectionList_countsNoRows(t *testing.T) {
	evSum, err := findings.MarshalEvidenceSummaryJSON(findings.EvidenceSummaryV1{
		MatcherOutcomes: []findings.MatcherOutcomeSummary{{Index: 0, Kind: "a", Passed: true}, {Index: 1, Kind: "b", Passed: false}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := findings.Finding{EvidenceSummary: evSum}
	ins := parseFindingEvidenceInspectionList(f)
	if ins == nil {
		t.Fatal("expected inspection")
	}
	if ins.DiffPointCount != 0 || ins.MatcherPassed != 1 || ins.MatcherFailed != 1 {
		t.Fatalf("got %+v", ins)
	}
}

func TestParseFindingEvidenceInspection_matcherOutcomesSortedByIndex(t *testing.T) {
	evSum, err := findings.MarshalEvidenceSummaryJSON(findings.EvidenceSummaryV1{
		MatcherOutcomes: []findings.MatcherOutcomeSummary{
			{Index: 2, Kind: "later", Passed: true},
			{Index: 0, Kind: "first", Passed: false},
			{Index: 1, Kind: "mid", Passed: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := findings.Finding{EvidenceSummary: evSum, BaselineExecutionID: "b1", MutatedExecutionID: "m1"}
	ins := parseFindingEvidenceInspection(f)
	if ins == nil || len(ins.MatcherOutcomes) != 3 {
		t.Fatalf("ins %+v", ins)
	}
	want := []MatcherOutcomeLine{
		{Index: 0, Kind: "first", Passed: false},
		{Index: 1, Kind: "mid", Passed: true},
		{Index: 2, Kind: "later", Passed: true},
	}
	for i := range want {
		if ins.MatcherOutcomes[i] != want[i] {
			t.Fatalf("i=%d got %+v want %+v", i, ins.MatcherOutcomes[i], want[i])
		}
	}
}

func TestNewFindingRead_fillsExecutionIDsFromEvidenceSummary(t *testing.T) {
	evSum, err := findings.MarshalEvidenceSummaryJSON(findings.EvidenceSummaryV1{
		BaselineExecutionID: "eb",
		MutatedExecutionID:  "em",
	})
	if err != nil {
		t.Fatal(err)
	}
	f := findings.Finding{
		ID:              "fid",
		ScanID:          "sid",
		RuleID:          "r",
		Category:        "c",
		Severity:        findings.SeverityLow,
		Summary:         "sum",
		EvidenceURI:     "/v1/findings/fid/evidence",
		EvidenceSummary: evSum,
	}
	r := NewFindingRead(f)
	if r.BaselineExecutionID != "eb" || r.MutatedExecutionID != "em" {
		t.Fatalf("read %+v", r)
	}
}

func TestFindingRead_readTrustLegendWireKeysMatchProofScripts(t *testing.T) {
	f := findings.Finding{
		ID: "550e8400-e29b-41d4-a716-446655440000", ScanID: "660e8400-e29b-41d4-a716-446655440001",
		RuleID: "r", Category: "c", Severity: findings.SeverityLow, Summary: "s", EvidenceURI: "/e",
	}
	raw, err := json.Marshal(NewFindingRead(f))
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	legendRaw, ok := top["read_trust_legend"]
	if !ok {
		t.Fatal("missing read_trust_legend")
	}
	var legend map[string]string
	if err := json.Unmarshal(legendRaw, &legend); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"severity", "rule_declared_confidence", "assessment_tier", "evidence_summary", "evidence_inspection", "operator_assessment"} {
		if legend[k] == "" {
			t.Fatalf("empty legend key %q", k)
		}
	}
}

func TestNewFindingRead_readTrustLegendStable(t *testing.T) {
	f := findings.Finding{
		ID:          "fid",
		ScanID:      "sid",
		RuleID:      "r",
		Category:    "c",
		Severity:    findings.SeverityLow,
		Summary:     "s",
		EvidenceURI: "/e",
	}
	r := NewFindingRead(f)
	if r.ReadTrustLegend.Severity == "" || r.ReadTrustLegend.EvidenceSummary == "" {
		t.Fatalf("legend %+v", r.ReadTrustLegend)
	}
	if !strings.Contains(r.ReadTrustLegend.AssessmentTier, "operator_assessment") {
		t.Fatalf("expected pointer to tier gloss: %q", r.ReadTrustLegend.AssessmentTier)
	}
}

func TestNewFindingRead_operatorAssessment_tierGuideAndMirroredCodes(t *testing.T) {
	evSum, err := findings.MarshalEvidenceSummaryJSON(findings.EvidenceSummaryV1{
		AssessmentTier:      "tentative",
		AssessmentNotes:     []string{" weak_note ", ""},
		InterpretationHints: []string{"hint_a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := findings.Finding{
		ID:              "fid",
		ScanID:          "sid",
		RuleID:          "r",
		Category:        "c",
		Severity:        findings.SeverityMedium,
		AssessmentTier:  "tentative",
		Summary:         "s",
		EvidenceURI:     "/e",
		EvidenceSummary: evSum,
	}
	r := NewFindingRead(f)
	if r.OperatorAssessment == nil {
		t.Fatal("expected operator_assessment")
	}
	if !strings.Contains(r.OperatorAssessment.EvidenceSufficiencyGuide, "tentative") {
		t.Fatalf("guide %q", r.OperatorAssessment.EvidenceSufficiencyGuide)
	}
	if len(r.OperatorAssessment.AssessmentNoteCodes) != 1 || r.OperatorAssessment.AssessmentNoteCodes[0] != "weak_note" {
		t.Fatalf("notes %+v", r.OperatorAssessment.AssessmentNoteCodes)
	}
	if len(r.OperatorAssessment.ScannerPolicyHints) != 1 || r.OperatorAssessment.ScannerPolicyHints[0] != "hint_a" {
		t.Fatalf("hints %+v", r.OperatorAssessment.ScannerPolicyHints)
	}
}

func TestNewFindingRead_operatorAssessment_omittedWhenEmptySignals(t *testing.T) {
	f := findings.Finding{
		ID:          "fid",
		ScanID:      "sid",
		RuleID:      "r",
		Category:    "c",
		Severity:    findings.SeverityLow,
		Summary:     "s",
		EvidenceURI: "/e",
	}
	r := NewFindingRead(f)
	if r.OperatorAssessment != nil {
		t.Fatalf("want nil, got %+v", r.OperatorAssessment)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	if _, hasOA := top["operator_assessment"]; hasOA {
		t.Fatalf("top-level operator_assessment should be omitted: %s", raw)
	}
}

func TestNewFindingRead_severityAndTierDistinctDocShape(t *testing.T) {
	f := findings.Finding{
		ID:                     "fid",
		ScanID:                 "sid",
		RuleID:                 "r",
		Category:               "c",
		Severity:               findings.SeverityHigh,
		RuleDeclaredConfidence: " low ",
		AssessmentTier:         " tentative ",
		Summary:                "human summary",
		EvidenceURI:            "/e",
	}
	r := NewFindingRead(f)
	if r.Severity != findings.SeverityHigh {
		t.Fatal(r.Severity)
	}
	if r.RuleDeclaredConfidence != "low" || r.AssessmentTier != "tentative" {
		t.Fatalf("trim %+v", r)
	}
	// summary is operator text; not trimmed aggressively here (stored summary)
	if r.Summary != "human summary" {
		t.Fatal(r.Summary)
	}
}
