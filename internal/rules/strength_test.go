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
