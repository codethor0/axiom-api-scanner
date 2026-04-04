package mutation

import (
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

func TestFindingOperatorSummary_confirmedUnchanged(t *testing.T) {
	s := findingOperatorSummary("r1", "GET", "/x", "detail", "confirmed", []string{"weak_body_similarity_matcher"}, nil)
	if s != "rule r1 matched for GET /x (detail)" {
		t.Fatal(s)
	}
}

func TestFindingOperatorSummary_tentativeAppendsNotesAndInterpretation(t *testing.T) {
	notes := []string{"weak_body_similarity_matcher", "similarity_min_score_0.85"}
	interp := findings.InterpretationHints("tentative", notes)
	s := findingOperatorSummary("r1", "GET", "/x", "detail", "tentative", notes, interp)
	want := "rule r1 matched for GET /x (detail); assessment: weak_body_similarity_matcher, similarity_min_score_0.85; interpretation: interpretation_body_similarity_min_below_0_9_keeps_tentative_tier"
	if s != want {
		t.Fatal(s)
	}
}

func TestFindingOperatorSummary_incompleteAppendsNotesAndInterpretation(t *testing.T) {
	notes := []string{"evidence_incomplete"}
	interp := findings.InterpretationHints("incomplete", notes)
	s := findingOperatorSummary("r1", "GET", "/x", "detail", "incomplete", notes, interp)
	want := "rule r1 matched for GET /x (detail); assessment: evidence_incomplete; interpretation: outcome_insufficient_evidence_for_confirmed_tier"
	if s != want {
		t.Fatal(s)
	}
}
