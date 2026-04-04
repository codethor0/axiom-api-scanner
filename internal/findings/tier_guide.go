package findings

import "strings"

// TierEvidenceSufficiencyGuide returns a stable, non-persisted sentence for API read models.
// It summarizes post-run assessment_tier only; it does not repeat target-specific fixture context.
func TierEvidenceSufficiencyGuide(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "confirmed":
		return "Post-run assessment is confirmed: matchers passed with complete evidence and no weak-signal tier cap applies to this finding row."
	case "tentative":
		return "Post-run assessment is tentative: matchers passed, but declared rule confidence, impact bucket, or weak matcher signals cap the tier below confirmed (see assessment_note_codes and scanner_policy_hints on this read model when present)."
	case "incomplete":
		return "Post-run assessment is incomplete: baseline/mutated linkage, HTTP status, or diff evaluation did not meet the bar for a confirmed tier on this row (see assessment_note_codes)."
	default:
		return ""
	}
}
