package v1

import (
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
)

func TestEvaluateRuleMatchers_statusUnchangedAndSimilarity(t *testing.T) {
	rule := rules.Rule{
		Matchers: []rules.Matcher{
			{Kind: rules.MatcherStatusCodeUnchanged},
			{Kind: rules.MatcherResponseBodySimilarity, ResponseBodySimilarity: &rules.ResponseBodySimilarityMatcher{MinScore: 0.5}},
		},
	}
	b := engine.ExecutionRecord{
		ScanID: "s1", ScanEndpointID: "e1",
		ResponseStatus:      200,
		ResponseBody:        `{"ok":true}`,
		ResponseContentType: "application/json",
	}
	u := engine.ExecutionRecord{
		ScanID: "s1", ScanEndpointID: "e1",
		ResponseStatus:      200,
		ResponseBody:        `{"ok":true}`,
		ResponseContentType: "application/json",
	}
	res := EvaluateRuleMatchers(rule, b, u)
	if !res.Pass || res.Incomplete {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateRuleMatchers_rejectsMismatchedEndpoints(t *testing.T) {
	rule := rules.Rule{Matchers: []rules.Matcher{{Kind: rules.MatcherStatusCodeUnchanged}}}
	b := engine.ExecutionRecord{ScanID: "s1", ScanEndpointID: "e1"}
	u := engine.ExecutionRecord{ScanID: "s1", ScanEndpointID: "e2"}
	res := EvaluateRuleMatchers(rule, b, u)
	if !res.Incomplete {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateRuleMatchers_statusDiffers(t *testing.T) {
	rule := rules.Rule{Matchers: []rules.Matcher{{Kind: rules.MatcherStatusDiffersFromBaseline}}}
	b := engine.ExecutionRecord{ScanID: "s", ScanEndpointID: "e", ResponseStatus: 200}
	u := engine.ExecutionRecord{ScanID: "s", ScanEndpointID: "e", ResponseStatus: 404}
	res := EvaluateRuleMatchers(rule, b, u)
	if !res.Pass || res.Incomplete {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateRuleMatchers_substring(t *testing.T) {
	rule := rules.Rule{Matchers: []rules.Matcher{
		{Kind: rules.MatcherResponseBodySubstring, ResponseBodySubstring: &rules.ResponseBodySubstringMatcher{Substring: "admin"}},
	}}
	u := engine.ExecutionRecord{ScanID: "s", ScanEndpointID: "e", ResponseBody: `{"role":"admin"}`}
	res := EvaluateRuleMatchers(rule, engine.ExecutionRecord{ScanID: "s", ScanEndpointID: "e"}, u)
	if !res.Pass {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateRuleMatchers_jsonPathEquals(t *testing.T) {
	rule := rules.Rule{Matchers: []rules.Matcher{
		{Kind: rules.MatcherJSONPathEquals, JSONPathEquals: &rules.JSONPathEqualsMatcher{Path: "role", Value: `"admin"`}},
	}}
	u := engine.ExecutionRecord{ScanID: "s", ScanEndpointID: "e", ResponseBody: `{"role":"admin"}`}
	res := EvaluateRuleMatchers(rule, engine.ExecutionRecord{ScanID: "s", ScanEndpointID: "e"}, u)
	if !res.Pass {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateRuleMatchers_headerDiffers(t *testing.T) {
	rule := rules.Rule{Matchers: []rules.Matcher{
		{Kind: rules.MatcherResponseHeaderDiffersFromBaseline, ResponseHeaderDiffersFromBaseline: &rules.ResponseHeaderDiffersFromBaselineMatcher{Name: "X-Test"}},
	}}
	b := engine.ExecutionRecord{
		ScanID: "s", ScanEndpointID: "e",
		ResponseHeaders: map[string]string{"X-Test": "a"},
	}
	u := engine.ExecutionRecord{
		ScanID: "s", ScanEndpointID: "e",
		ResponseHeaders: map[string]string{"X-Test": "b"},
	}
	res := EvaluateRuleMatchers(rule, b, u)
	if !res.Pass {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateRuleMatchers_unsupportedKindIncomplete(t *testing.T) {
	rule := rules.Rule{Matchers: []rules.Matcher{{Kind: rules.MatcherKind("unknown_kind")}}}
	b := engine.ExecutionRecord{ScanID: "s", ScanEndpointID: "e"}
	u := engine.ExecutionRecord{ScanID: "s", ScanEndpointID: "e"}
	res := EvaluateRuleMatchers(rule, b, u)
	if !res.Incomplete || res.Pass {
		t.Fatalf("%+v", res)
	}
}

func TestEvaluateRuleMatchers_similarityFalsePositiveResistance(t *testing.T) {
	rule := rules.Rule{Matchers: []rules.Matcher{
		{Kind: rules.MatcherResponseBodySimilarity, ResponseBodySimilarity: &rules.ResponseBodySimilarityMatcher{MinScore: 0.99}},
	}}
	b := engine.ExecutionRecord{ScanID: "s", ScanEndpointID: "e", ResponseBody: `{"a":1}`}
	u := engine.ExecutionRecord{ScanID: "s", ScanEndpointID: "e", ResponseBody: `{"b":2}`}
	res := EvaluateRuleMatchers(rule, b, u)
	if res.Pass || res.Incomplete {
		t.Fatalf("expected failure, got %+v", res)
	}
}
