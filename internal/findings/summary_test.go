package findings

import (
	"encoding/json"
	"testing"
)

func TestMarshalEvidenceSummaryJSON_roundTrip(t *testing.T) {
	raw, err := MarshalEvidenceSummaryJSON(EvidenceSummaryV1{
		RuleID:         "r1",
		AssessmentTier: "tentative",
		RuleSeverity:   "medium",
		MatcherOutcomes: []MatcherOutcomeSummary{
			{Index: 0, Kind: "status_code_unchanged", Passed: true, Summary: "ok"},
		},
		DiffPoints: []string{"all_matchers_passed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["schema_version"].(float64) != 1 {
		t.Fatalf("%v", m["schema_version"])
	}
}
