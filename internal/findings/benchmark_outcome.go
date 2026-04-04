package findings

import "strings"

// Harness-only outcome classes for benchmark stdout and docs (not persisted on findings).
const (
	BenchOutcomeConfirmedUseful       = "outcome_confirmed_useful"
	BenchOutcomeTentativeWeakSignal   = "outcome_tentative_weak_signal"
	BenchOutcomeFixtureLimitedNoRow   = "outcome_fixture_limited_no_row"
	BenchOutcomeNotExercisedOnTarget  = "outcome_not_exercised_on_target"
)

// BenchmarkRuleFamilyKey returns the stable rule_family_coverage JSON key for a builtin benchmark rule_id.
func BenchmarkRuleFamilyKey(ruleID string) string {
	switch strings.TrimSpace(ruleID) {
	case "axiom.idor.path_swap.v1":
		return "idor_path_or_query_swap"
	case "axiom.mass.privilege_merge.v1":
		return "mass_assignment_privilege_injection"
	case "axiom.pathnorm.variant.v1":
		return "path_normalization_bypass"
	case "axiom.ratelimit.header_rotate.v1":
		return "rate_limit_header_rotation"
	default:
		return "unknown_rule_family"
	}
}

// BenchmarkOutcomeClass maps a rule's result on one benchmark scan to a single outcome label.
// findingRowCount is how many finding rows exist for that rule after mutations.
// When findingRowCount > 0, assessmentTier must match those rows (this benchmark uses one tier per rule per scan).
func BenchmarkOutcomeClass(targetLabel, ruleID, assessmentTier string, findingRowCount int) string {
	label := strings.TrimSpace(targetLabel)
	rule := strings.TrimSpace(ruleID)
	tier := strings.ToLower(strings.TrimSpace(assessmentTier))
	if findingRowCount < 0 {
		findingRowCount = 0
	}
	if findingRowCount == 0 {
		if label == BenchTargetLabelHTTPBinV1 && rule == "axiom.ratelimit.header_rotate.v1" {
			return BenchOutcomeFixtureLimitedNoRow
		}
		return BenchOutcomeNotExercisedOnTarget
	}
	switch tier {
	case "confirmed":
		return BenchOutcomeConfirmedUseful
	case "tentative", "incomplete":
		return BenchOutcomeTentativeWeakSignal
	default:
		return BenchOutcomeTentativeWeakSignal
	}
}
