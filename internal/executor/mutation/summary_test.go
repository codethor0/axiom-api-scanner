package mutation

import "testing"

func TestFindingOperatorSummary_confirmedUnchanged(t *testing.T) {
	s := findingOperatorSummary("r1", "GET", "/x", "detail", "confirmed", []string{"weak_body_similarity_matcher"})
	if s != "rule r1 matched for GET /x (detail)" {
		t.Fatal(s)
	}
}

func TestFindingOperatorSummary_tentativeAppendsNotes(t *testing.T) {
	notes := []string{"weak_body_similarity_matcher", "similarity_min_score_0.85"}
	s := findingOperatorSummary("r1", "GET", "/x", "detail", "tentative", notes)
	want := "rule r1 matched for GET /x (detail); assessment: weak_body_similarity_matcher, similarity_min_score_0.85"
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
