package findings

import (
	"reflect"
	"testing"
)

func TestInterpretationHints_confirmedNil(t *testing.T) {
	if h := InterpretationHints("confirmed", nil); h != nil {
		t.Fatalf("%v", h)
	}
	if h := InterpretationHints("confirmed", []string{}); h != nil {
		t.Fatalf("%v", h)
	}
}

func TestInterpretationHints_incomplete(t *testing.T) {
	h := InterpretationHints("incomplete", []string{"evidence_incomplete"})
	want := []string{"outcome_insufficient_evidence_for_confirmed_tier"}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("%v", h)
	}
}

func TestInterpretationHints_tentative_weakSimilarity(t *testing.T) {
	notes := []string{"weak_body_similarity_matcher", "similarity_min_score_0.85"}
	h := InterpretationHints("tentative", notes)
	want := []string{"interpretation_body_similarity_min_below_0_9_keeps_tentative_tier"}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("%v", h)
	}
}

func TestInterpretationHints_tentative_substring(t *testing.T) {
	h := InterpretationHints("tentative", []string{"weak_body_substring_matcher"})
	want := []string{"interpretation_body_substring_matcher_keeps_tentative_tier"}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("%v", h)
	}
}

func TestInterpretationHints_tentative_declaredLowConfidence(t *testing.T) {
	h := InterpretationHints("tentative", []string{"rule_declared_low_confidence"})
	want := []string{"interpretation_declared_rule_confidence_caps_tier"}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("%v", h)
	}
}

func TestInterpretationHints_tentative_lowSeverity(t *testing.T) {
	h := InterpretationHints("tentative", []string{"low_signal_severity_bucket"})
	want := []string{"interpretation_impact_severity_bucket_caps_tier"}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("%v", h)
	}
}
