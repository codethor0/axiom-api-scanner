package rules

import "testing"

func TestRuleUsesWeakMatcherSignal(t *testing.T) {
	r := Rule{Matchers: []Matcher{
		{Kind: MatcherStatusCodeUnchanged},
		{Kind: MatcherResponseBodySubstring, ResponseBodySubstring: &ResponseBodySubstringMatcher{Substring: "x"}},
	}}
	if !RuleUsesWeakMatcherSignal(r) {
		t.Fatal("substring should be weak")
	}
	r2 := Rule{Matchers: []Matcher{
		{Kind: MatcherResponseBodySimilarity, ResponseBodySimilarity: &ResponseBodySimilarityMatcher{MinScore: 0.89}},
	}}
	if !RuleUsesWeakMatcherSignal(r2) {
		t.Fatal("similarity below 0.9 should be weak")
	}
	r3 := Rule{Matchers: []Matcher{
		{Kind: MatcherResponseBodySimilarity, ResponseBodySimilarity: &ResponseBodySimilarityMatcher{MinScore: 0.91}},
	}}
	if RuleUsesWeakMatcherSignal(r3) {
		t.Fatal("similarity >= 0.9 not weak signal")
	}
}

func TestWeakMatcherAssessmentNotes_substring(t *testing.T) {
	r := Rule{Matchers: []Matcher{
		{Kind: MatcherResponseBodySubstring, ResponseBodySubstring: &ResponseBodySubstringMatcher{Substring: "x"}},
	}}
	got := WeakMatcherAssessmentNotes(r)
	if len(got) != 1 || got[0] != "weak_body_substring_matcher" {
		t.Fatalf("%v", got)
	}
}

func TestWeakMatcherAssessmentNotes_similarityScoreToken(t *testing.T) {
	r := Rule{Matchers: []Matcher{
		{Kind: MatcherResponseBodySimilarity, ResponseBodySimilarity: &ResponseBodySimilarityMatcher{MinScore: 0.85}},
	}}
	got := WeakMatcherAssessmentNotes(r)
	if len(got) != 2 || got[0] != "weak_body_similarity_matcher" || got[1] != "similarity_min_score_0.85" {
		t.Fatalf("%v", got)
	}
	r2 := Rule{Matchers: []Matcher{
		{Kind: MatcherResponseBodySimilarity, ResponseBodySimilarity: &ResponseBodySimilarityMatcher{MinScore: 0.8}},
	}}
	got2 := WeakMatcherAssessmentNotes(r2)
	if len(got2) != 2 || got2[1] != "similarity_min_score_0.8" {
		t.Fatalf("%v", got2)
	}
}
