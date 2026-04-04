package v1

import (
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
)

func TestEvaluateRuleMatchersWithOutcomes_collectsRows(t *testing.T) {
	rule := rules.Rule{
		Matchers: []rules.Matcher{
			{Kind: rules.MatcherStatusCodeUnchanged},
			{Kind: rules.MatcherResponseBodySimilarity, ResponseBodySimilarity: &rules.ResponseBodySimilarityMatcher{MinScore: 0.5}},
		},
	}
	b := engine.ExecutionRecord{
		ScanID: "s1", ScanEndpointID: "e1",
		ResponseStatus: 200,
		ResponseBody:   `{"ok":true}`,
	}
	u := engine.ExecutionRecord{
		ScanID: "s1", ScanEndpointID: "e1",
		ResponseStatus: 200,
		ResponseBody:   `{"ok":true}`,
	}
	w := EvaluateRuleMatchersWithOutcomes(rule, b, u)
	if !w.Pass || w.Incomplete {
		t.Fatalf("%+v", w)
	}
	if len(w.Outcomes) != 2 {
		t.Fatalf("%+v", w.Outcomes)
	}
	if w.Outcomes[0].Kind != string(rules.MatcherStatusCodeUnchanged) || !w.Outcomes[0].Passed {
		t.Fatalf("%+v", w.Outcomes[0])
	}
	if w.Outcomes[0].Summary == "" {
		t.Fatal("expected summary line")
	}
}
