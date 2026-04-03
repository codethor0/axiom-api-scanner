package findings

import "testing"

func TestAssessFindingTier_incompleteEvidence(t *testing.T) {
	tier, notes := AssessFindingTier(SeverityHigh, "high", false, false)
	if tier != "incomplete" || len(notes) != 1 {
		t.Fatalf("%s %v", tier, notes)
	}
}

func TestAssessFindingTier_weakMatcher(t *testing.T) {
	tier, notes := AssessFindingTier(SeverityHigh, "high", true, true)
	if tier != "tentative" {
		t.Fatal(tier)
	}
	if len(notes) == 0 {
		t.Fatal(notes)
	}
}

func TestAssessFindingTier_lowDeclaredConfidence(t *testing.T) {
	tier, _ := AssessFindingTier(SeverityHigh, "low", false, true)
	if tier != "tentative" {
		t.Fatal(tier)
	}
}

func TestAssessFindingTier_lowSeverityBucket(t *testing.T) {
	tier, _ := AssessFindingTier(SeverityLow, "high", false, true)
	if tier != "tentative" {
		t.Fatal(tier)
	}
}

func TestAssessFindingTier_confirmed(t *testing.T) {
	tier, notes := AssessFindingTier(SeverityHigh, "high", false, true)
	if tier != "confirmed" {
		t.Fatalf("%s %v", tier, notes)
	}
}
