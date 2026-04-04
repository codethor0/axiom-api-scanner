package findings

import "strings"

// AssessFindingTier derives assessment tier from severity, declared rule confidence, weak-matcher
// notes (non-empty => tentative with those codes), and evidence completeness. No ML or speculative scoring.
func AssessFindingTier(sev Severity, ruleDeclConfidence string, weakMatcherNotes []string, evidenceComplete bool) (tier string, notes []string) {
	if !evidenceComplete {
		return "incomplete", []string{"evidence_incomplete"}
	}
	if len(weakMatcherNotes) > 0 {
		return "tentative", append([]string(nil), weakMatcherNotes...)
	}
	dc := strings.ToLower(strings.TrimSpace(ruleDeclConfidence))
	if dc == "low" {
		return "tentative", []string{"rule_declared_low_confidence"}
	}
	switch sev {
	case SeverityInfo, SeverityLow:
		return "tentative", []string{"low_signal_severity_bucket"}
	default:
		return "confirmed", nil
	}
}
