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
	if m["rule_severity"] != "medium" || m["impact_severity"] != "medium" {
		t.Fatalf("want mirrored impact keys, got %#v %#v", m["rule_severity"], m["impact_severity"])
	}
}

func TestEvidenceSummaryV1_unmarshal_legacyRuleSeverity(t *testing.T) {
	const legacy = `{"schema_version":1,"rule_severity":"high","assessment_tier":"confirmed"}`
	var v EvidenceSummaryV1
	if err := json.Unmarshal([]byte(legacy), &v); err != nil {
		t.Fatal(err)
	}
	if v.RuleSeverity != "high" || v.ImpactSeverity != "high" {
		t.Fatalf("%+v", v)
	}
}

func TestEvidenceSummaryV1_unmarshal_impactSeverityOnly(t *testing.T) {
	const blob = `{"schema_version":1,"impact_severity":"low","assessment_tier":"tentative"}`
	var v EvidenceSummaryV1
	if err := json.Unmarshal([]byte(blob), &v); err != nil {
		t.Fatal(err)
	}
	if v.RuleSeverity != "low" || v.ImpactSeverity != "low" {
		t.Fatalf("%+v", v)
	}
}
