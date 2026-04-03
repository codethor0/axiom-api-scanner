package rules

import (
	"fmt"
	"strings"
)

// Validate checks required DSL fields and value constraints.
func Validate(r Rule) error {
	var errs []string
	if strings.TrimSpace(r.ID) == "" {
		errs = append(errs, "id is required")
	}
	if strings.TrimSpace(r.Name) == "" {
		errs = append(errs, "name is required")
	}
	if strings.TrimSpace(r.Category) == "" {
		errs = append(errs, "category is required")
	}
	if strings.TrimSpace(r.Severity) == "" {
		errs = append(errs, "severity is required")
	}
	if strings.TrimSpace(r.Confidence) == "" {
		errs = append(errs, "confidence is required")
	}
	switch r.Safety.Mode {
	case SafetyPassive, SafetySafe, SafetyFull:
	default:
		errs = append(errs, fmt.Sprintf("safety.mode must be one of %q, %q, %q", SafetyPassive, SafetySafe, SafetyFull))
	}
	if len(r.Target.Methods) == 0 {
		errs = append(errs, "target.methods must include at least one HTTP method")
	}
	if strings.TrimSpace(r.Target.Where) == "" {
		errs = append(errs, "target.where is required")
	}
	if len(r.Mutations) == 0 {
		errs = append(errs, "mutations must include at least one step")
	}
	for i, m := range r.Mutations {
		if err := m.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("mutations[%d]: %v", i, err))
		}
	}
	if len(r.Matchers) == 0 {
		errs = append(errs, "matchers must include at least one matcher")
	}
	for i, m := range r.Matchers {
		if err := m.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("matchers[%d]: %v", i, err))
		}
	}
	if len(r.References) == 0 {
		errs = append(errs, "references must include at least one citation")
	}
	if err := ValidateRuleConfidence(r); err != nil {
		errs = append(errs, err.Error())
	}
	if err := ValidateSafePassiveV1(r); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("rule validation failed: %s", strings.Join(errs, "; "))
}
