package findings

import "strings"

// InterpretationHints are stable, product-agnostic strings for operators and integrators. They explain what
// the assessment tier means in terms of policy (not target-specific fixture behavior). Omitted for confirmed
// findings when the tier is confirmed with no assessment notes. Empty slice when nothing to add beyond assessment_notes.
func InterpretationHints(tier string, assessmentNotes []string) []string {
	t := strings.TrimSpace(strings.ToLower(tier))
	switch t {
	case "confirmed":
		return nil
	case "incomplete":
		return []string{"outcome_insufficient_evidence_for_confirmed_tier"}
	case "tentative":
		return tentativeInterpretationHints(assessmentNotes)
	default:
		return nil
	}
}

func tentativeInterpretationHints(notes []string) []string {
	var hasWeakSim, hasWeakSub, hasLowConf, hasLowSev bool
	for _, n := range notes {
		switch {
		case n == "weak_body_similarity_matcher" || strings.HasPrefix(n, "similarity_min_score_"):
			hasWeakSim = true
		case n == "weak_body_substring_matcher":
			hasWeakSub = true
		case n == "rule_declared_low_confidence":
			hasLowConf = true
		case n == "low_signal_severity_bucket":
			hasLowSev = true
		}
	}
	var out []string
	if hasLowConf {
		out = append(out, "interpretation_declared_rule_confidence_caps_tier")
	}
	if hasLowSev {
		out = append(out, "interpretation_impact_severity_bucket_caps_tier")
	}
	if hasWeakSub {
		out = append(out, "interpretation_body_substring_matcher_keeps_tentative_tier")
	}
	if hasWeakSim {
		out = append(out, "interpretation_body_similarity_min_below_0_9_keeps_tentative_tier")
	}
	return out
}
