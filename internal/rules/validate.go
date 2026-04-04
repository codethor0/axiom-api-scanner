package rules

import (
	"fmt"
	"strings"
)

// Validate checks required DSL fields and value constraints.
func Validate(r Rule) error {
	var errs []string
	if strings.TrimSpace(r.ID) == "" {
		errs = append(errs, "[metadata] id: must be non-empty (stable rule identifier)")
	}
	if strings.TrimSpace(r.Name) == "" {
		errs = append(errs, "[metadata] name: must be non-empty (human title)")
	}
	if strings.TrimSpace(r.Category) == "" {
		errs = append(errs, "[metadata] category: must be non-empty (taxonomy bucket)")
	}
	if strings.TrimSpace(r.Severity) == "" {
		errs = append(errs, "[metadata] severity: must be non-empty (impact hint for findings)")
	}
	if strings.TrimSpace(r.Confidence) == "" {
		errs = append(errs, "[metadata] confidence: must be set to high, medium, or low (author-expected signal strength)")
	}
	switch r.Safety.Mode {
	case SafetyPassive, SafetySafe, SafetyFull:
	default:
		errs = append(errs, fmt.Sprintf("[safety] mode: must be %q, %q, or %q (got %q)", SafetyPassive, SafetySafe, SafetyFull, r.Safety.Mode))
	}
	if len(r.Target.Methods) == 0 {
		errs = append(errs, "[target] methods: list at least one HTTP method this rule applies to")
	}
	if strings.TrimSpace(r.Target.Where) == "" {
		errs = append(errs, "[target] where: must describe where mutations apply (e.g. path_params.id, json_body, query.id)")
	}
	if len(r.Mutations) == 0 {
		errs = append(errs, "[mutations] must include at least one typed mutation step")
	}
	for i, m := range r.Mutations {
		if err := m.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("[mutations[%d]] %v", i, err))
		}
	}
	if len(r.Matchers) == 0 {
		errs = append(errs, "[matchers] must include at least one response matcher")
	}
	for i, m := range r.Matchers {
		if err := m.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("[matchers[%d]] %v", i, err))
		}
	}
	if len(r.References) == 0 {
		errs = append(errs, "[references] add at least one citation URL or reference string")
	}
	if err := ValidateRuleConfidence(r); err != nil {
		errs = append(errs, "[metadata] "+err.Error())
	}
	if err := ValidateSafePassiveV1(r); err != nil {
		errs = append(errs, err.Error())
	}
	return NewValidationError(errs)
}
