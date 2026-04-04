package mutation

import "testing"

func TestFindingOperatorSummary_confirmedUnchanged(t *testing.T) {
	s := findingOperatorSummary("r1", "GET", "/x", "detail", "confirmed", []string{"weak_matcher_signal"})
	if s != "rule r1 matched for GET /x (detail)" {
		t.Fatal(s)
	}
}

func TestFindingOperatorSummary_tentativeAppendsNotes(t *testing.T) {
	s := findingOperatorSummary("r1", "GET", "/x", "detail", "tentative", []string{"weak_matcher_signal"})
	want := "rule r1 matched for GET /x (detail); assessment: weak_matcher_signal"
	if s != want {
		t.Fatal(s)
	}
}

func TestFindingOperatorSummary_incompleteAppendsNotes(t *testing.T) {
	s := findingOperatorSummary("r1", "GET", "/x", "detail", "incomplete", []string{"evidence_incomplete"})
	if s != "rule r1 matched for GET /x (detail); assessment: evidence_incomplete" {
		t.Fatal(s)
	}
}
