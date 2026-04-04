package api

import (
	"testing"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

func TestNewFindingRead_evidenceInspection(t *testing.T) {
	t.Parallel()
	raw, err := findings.MarshalEvidenceSummaryJSON(findings.EvidenceSummaryV1{
		BaselineExecutionID: "b-ex",
		MutatedExecutionID:  "m-ex",
		MatcherOutcomes: []findings.MatcherOutcomeSummary{
			{Index: 0, Kind: "status_differs_from_baseline", Passed: true, Summary: "ignored"},
			{Index: 1, Kind: "response_body_substring", Passed: false},
		},
		DiffPoints: []string{"a", "b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := findings.Finding{
		ID:                     "f1",
		ScanID:                 "s1",
		RuleID:                 "r1",
		Category:               "c",
		Severity:               findings.SeverityHigh,
		RuleDeclaredConfidence: "high",
		AssessmentTier:         "confirmed",
		Summary:                "sum",
		EvidenceSummary:        raw,
		EvidenceURI:            "/v1/findings/f1/evidence",
		BaselineExecutionID:    "b-ex",
		MutatedExecutionID:     "m-ex",
		CreatedAt:              time.Unix(1, 0).UTC(),
	}
	r := NewFindingRead(f)
	if r.EvidenceInspection == nil {
		t.Fatal("expected inspection")
	}
	if r.EvidenceInspection.BaselineExecutionID != "b-ex" || r.EvidenceInspection.MutatedExecutionID != "m-ex" {
		t.Fatalf("ids %+v", r.EvidenceInspection)
	}
	if r.EvidenceInspection.DiffPointCount != 2 || len(r.EvidenceInspection.MatcherOutcomes) != 2 {
		t.Fatalf("outcomes/diff %+v", r.EvidenceInspection)
	}
	if r.EvidenceInspection.MatcherOutcomes[0].Kind != "status_differs_from_baseline" || !r.EvidenceInspection.MatcherOutcomes[0].Passed {
		t.Fatalf("m0 %+v", r.EvidenceInspection.MatcherOutcomes[0])
	}
	if r.EvidenceInspection.MatcherOutcomes[1].Passed {
		t.Fatal("m1 should be false")
	}
}

func TestNewFindingRead_columnIDsWithoutSummaryBody(t *testing.T) {
	t.Parallel()
	f := findings.Finding{
		ID:                  "f1",
		ScanID:              "s1",
		RuleID:              "r1",
		Severity:            findings.SeverityLow,
		EvidenceURI:         "/e",
		BaselineExecutionID: "b-only",
		MutatedExecutionID:  "m-only",
		CreatedAt:           time.Unix(0, 0).UTC(),
	}
	r := NewFindingRead(f)
	if r.EvidenceInspection == nil || r.EvidenceInspection.BaselineExecutionID != "b-only" {
		t.Fatalf("%+v", r.EvidenceInspection)
	}
}

func TestNewFindingRead_invalidEvidenceSummaryStillLinksColumns(t *testing.T) {
	t.Parallel()
	f := findings.Finding{
		ID:                  "f1",
		ScanID:              "s1",
		RuleID:              "r1",
		Severity:            findings.SeverityLow,
		EvidenceSummary:     []byte(`not-json`),
		EvidenceURI:         "/e",
		BaselineExecutionID: "bx",
		CreatedAt:           time.Unix(0, 0).UTC(),
	}
	r := NewFindingRead(f)
	if r.EvidenceInspection == nil || r.EvidenceInspection.BaselineExecutionID != "bx" {
		t.Fatalf("%+v", r.EvidenceInspection)
	}
}
