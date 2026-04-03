package findings

import "strings"

// AssessFindingTier derives finding_status / confidence tier from severity, declared rule
// confidence, matcher strength, and evidence completeness. No ML or speculative scoring.
func AssessFindingTier(sev Severity, ruleDeclConfidence string, weakMatcherSignal bool, evidenceComplete bool) (tier string, notes []string) {
	if !evidenceComplete {
		return "incomplete", []string{"evidence_incomplete"}
	}
	dc := strings.ToLower(strings.TrimSpace(ruleDeclConfidence))
	if weakMatcherSignal {
		notes = append(notes, "weak_matcher_signal")
		return "tentative", notes
	}
	if dc == "low" {
		notes = append(notes, "rule_declared_low_confidence")
		return "tentative", notes
	}
	switch sev {
	case SeverityInfo, SeverityLow:
		notes = append(notes, "low_signal_severity_bucket")
		return "tentative", notes
	default:
		return "confirmed", notes
	}
}
