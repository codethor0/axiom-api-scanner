package rules

import (
	"fmt"
	"strings"
)

// V1Family returns the planner family for a rule whose first mutation determines class.
// Callers enforcing a single safe mutation should use that sole mutation.
func V1Family(m Mutation) string {
	switch m.Kind {
	case MutationReplacePathParam, MutationReplaceQueryParam:
		return "idor"
	case MutationMergeJSONFields:
		return "mass_assignment"
	case MutationPathNormalizationVariant:
		return "path_normalization"
	case MutationRotateRequestHeaders:
		return "rate_limit_headers"
	default:
		return ""
	}
}

// ValidateRuleConfidence requires documented confidence labels on safe/passive/full rules.
func ValidateRuleConfidence(r Rule) error {
	c := strings.ToLower(strings.TrimSpace(r.Confidence))
	switch c {
	case "high", "medium", "low":
		return nil
	default:
		return fmt.Errorf("confidence must be one of high, medium, low (got %q)", r.Confidence)
	}
}

// ValidateSafePassiveV1 enforces single-mutation clarity, non-contradictory matchers, and
// per-family matcher allowlists for safety.mode safe and passive only.
// SafetyFull rules skip this (they may combine steps for advanced workflows).
func ValidateSafePassiveV1(r Rule) error {
	if r.Safety.Mode != SafetySafe && r.Safety.Mode != SafetyPassive {
		return nil
	}
	if len(r.Mutations) != 1 {
		return fmt.Errorf("safe/passive V1 rules require exactly one mutation (got %d); split multi-step checks into separate rules (documented limitation)", len(r.Mutations))
	}
	fam := V1Family(r.Mutations[0])
	if fam == "" {
		return fmt.Errorf("unsupported mutation for V1 safe rule")
	}
	if err := validateNoConflictingMatchers(r.Matchers); err != nil {
		return err
	}
	allowed := familyAllowedMatchers(fam)
	var headerish int
	for i, m := range r.Matchers {
		if !allowed[m.Kind] {
			return fmt.Errorf("matchers[%d]: kind %q is not allowed for V1 family %q on safe/passive rules", i, m.Kind, fam)
		}
		if isHeaderishMatcher(m.Kind) {
			headerish++
		}
		if m.Kind == MatcherResponseBodySimilarity && m.ResponseBodySimilarity != nil {
			if m.ResponseBodySimilarity.MinScore < 0.75 {
				return fmt.Errorf("matchers[%d]: response_body_similarity.min_score must be >= 0.75 for safe/passive rules", i)
			}
		}
	}
	switch fam {
	case "rate_limit_headers":
		if headerish == 0 {
			return fmt.Errorf("rate_limit_headers rules require at least one of header_present, header_absent, response_header_differs_from_baseline")
		}
	}
	return nil
}

func isHeaderishMatcher(k MatcherKind) bool {
	switch k {
	case MatcherHeaderPresent, MatcherHeaderAbsent, MatcherResponseHeaderDiffersFromBaseline:
		return true
	default:
		return false
	}
}

func validateNoConflictingMatchers(matchers []Matcher) error {
	var unchanged, differs bool
	for _, m := range matchers {
		switch m.Kind {
		case MatcherStatusCodeUnchanged:
			unchanged = true
		case MatcherStatusDiffersFromBaseline:
			differs = true
		}
	}
	if unchanged && differs {
		return fmt.Errorf("matchers cannot combine status_code_unchanged with status_differs_from_baseline")
	}
	return nil
}

func familyAllowedMatchers(fam string) map[MatcherKind]bool {
	// Body/path-focused matchers common to idor, mass_assignment, path_normalization.
	bodyPath := map[MatcherKind]bool{
		MatcherStatusCodeUnchanged:                  true,
		MatcherStatusDiffersFromBaseline:            true,
		MatcherResponseBodySimilarity:               true,
		MatcherJSONPathAbsent:                       true,
		MatcherJSONPathEquals:                       true,
		MatcherStatusIn:                             true,
		MatcherResponseBodySubstring:                true,
		MatcherHeaderPresent:                        false,
		MatcherHeaderAbsent:                         false,
		MatcherResponseHeaderDiffersFromBaseline:    false,
	}
	headerScope := map[MatcherKind]bool{
		MatcherStatusCodeUnchanged:                  true,
		MatcherStatusDiffersFromBaseline:            true,
		MatcherResponseBodySimilarity:               true,
		MatcherJSONPathAbsent:                       true,
		MatcherJSONPathEquals:                       true,
		MatcherStatusIn:                             true,
		MatcherResponseBodySubstring:                true,
		MatcherHeaderPresent:                        true,
		MatcherHeaderAbsent:                         true,
		MatcherResponseHeaderDiffersFromBaseline:    true,
	}
	switch fam {
	case "idor", "mass_assignment":
		return bodyPath
	case "path_normalization":
		return bodyPath
	case "rate_limit_headers":
		return headerScope
	default:
		return map[MatcherKind]bool{}
	}
}
