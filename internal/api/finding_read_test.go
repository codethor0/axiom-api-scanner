package api

import (
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
		ID:             "fid",
		ScanID:         "sid",
		RuleID:         "r",
		Category:       "c",
		Severity:       findings.SeverityLow,
		Summary:        "sum",
		EvidenceURI:    "/v1/findings/fid/evidence",
		EvidenceSummary: evSum,
	}
	r := NewFindingRead(f)
	if r.BaselineExecutionID != "eb" || r.MutatedExecutionID != "em" {
		t.Fatalf("read %+v", r)
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
