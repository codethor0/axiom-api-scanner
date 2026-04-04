package findings

import (
	"strings"
	"testing"
)

func TestTierEvidenceSufficiencyGuide(t *testing.T) {
	if g := TierEvidenceSufficiencyGuide("confirmed"); g == "" || !containsAll(g, []string{"confirmed", "matchers"}) {
		t.Fatalf("%q", g)
	}
	if g := TierEvidenceSufficiencyGuide("tentative "); g == "" || !containsAll(g, []string{"tentative", "weak"}) {
		t.Fatalf("%q", g)
	}
	if g := TierEvidenceSufficiencyGuide("incomplete"); g == "" || !containsAll(g, []string{"incomplete"}) {
		t.Fatalf("%q", g)
	}
	if TierEvidenceSufficiencyGuide("") != "" || TierEvidenceSufficiencyGuide("unknown") != "" {
		t.Fatal()
	}
}

func containsAll(s string, parts []string) bool {
	for _, p := range parts {
		if p == "" {
			continue
		}
		if !containsFold(s, p) {
			return false
		}
	}
	return true
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
