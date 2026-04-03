package rules

// RuleUsesWeakMatcherSignal reports matchers that alone are fragile for "confirmed" findings
// (substring / low-threshold similarity).
func RuleUsesWeakMatcherSignal(r Rule) bool {
	for _, m := range r.Matchers {
		switch m.Kind {
		case MatcherResponseBodySubstring:
			return true
		case MatcherResponseBodySimilarity:
			if m.ResponseBodySimilarity != nil && m.ResponseBodySimilarity.MinScore < 0.9 {
				return true
			}
		}
	}
	return false
}
