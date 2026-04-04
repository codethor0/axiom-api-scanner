package findings

import "testing"

func TestAssessFindingTier_incompleteEvidence(t *testing.T) {
	tier, notes := AssessFindingTier(SeverityHigh, "high", nil, false)
	if tier != "incomplete" || len(notes) != 1 {
		t.Fatalf("%s %v", tier, notes)
	}
}

func TestAssessFindingTier_weakMatcher(t *testing.T) {
	weak := []string{"weak_body_similarity_matcher", "similarity_min_score_0.85"}
	tier, notes := AssessFindingTier(SeverityHigh, "high", weak, true)
	if tier != "tentative" {
		t.Fatal(tier)
	}
	if len(notes) != 2 || notes[0] != weak[0] || notes[1] != weak[1] {
		t.Fatalf("%v", notes)
	}
}

func TestAssessFindingTier_lowDeclaredConfidence(t *testing.T) {
	tier, notes := AssessFindingTier(SeverityHigh, "low", nil, true)
	if tier != "tentative" || len(notes) != 1 || notes[0] != "rule_declared_low_confidence" {
		t.Fatalf("%s %v", tier, notes)
	}
}

func TestAssessFindingTier_lowSeverityBucket(t *testing.T) {
	tier, notes := AssessFindingTier(SeverityLow, "high", nil, true)
	if tier != "tentative" || len(notes) != 1 || notes[0] != "low_signal_severity_bucket" {
		t.Fatalf("%s %v", tier, notes)
	}
}

func TestAssessFindingTier_confirmed(t *testing.T) {
	tier, notes := AssessFindingTier(SeverityHigh, "high", nil, true)
	if tier != "confirmed" {
		t.Fatalf("%s %v", tier, notes)
	}
	if notes != nil {
		t.Fatalf("expected nil notes for confirmed, got %v", notes)
	}
}
