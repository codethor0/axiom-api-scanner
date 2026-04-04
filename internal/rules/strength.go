package rules

import (
	"strconv"
	"strings"
)

// WeakMatcherAssessmentNotes returns stable assessment note codes when the rule uses matchers
// treated as weak signals for "confirmed" tier (body substring, or body similarity with min_score < 0.9).
// Order follows rule matcher declaration order; empty when none apply.
func WeakMatcherAssessmentNotes(r Rule) []string {
	var out []string
	for _, m := range r.Matchers {
		switch m.Kind {
		case MatcherResponseBodySubstring:
			out = append(out, "weak_body_substring_matcher")
		case MatcherResponseBodySimilarity:
			if m.ResponseBodySimilarity != nil && m.ResponseBodySimilarity.MinScore < 0.9 {
				out = append(out, "weak_body_similarity_matcher")
				out = append(out, "similarity_min_score_"+formatAssessScore(m.ResponseBodySimilarity.MinScore))
			}
		}
	}
	return out
}

func formatAssessScore(v float64) string {
	s := strconv.FormatFloat(v, 'f', 4, 64)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	if s == "" {
		return "0"
	}
	return s
}

// RuleUsesWeakMatcherSignal reports whether any matcher in the rule is a weak signal source.
func RuleUsesWeakMatcherSignal(r Rule) bool {
	return len(WeakMatcherAssessmentNotes(r)) > 0
}
