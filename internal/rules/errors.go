package rules

import (
	"fmt"
	"strings"
)

// ValidationError formats multi-issue rule validation for operators (API and CLI).
type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "rule validation failed"
	}
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "rule validation failed (%d issues):\n", len(e.Issues))
	for i, line := range e.Issues {
		_, _ = fmt.Fprintf(&b, "  %d. %s\n", i+1, line)
	}
	return strings.TrimRight(b.String(), "\n")
}

// NewValidationError returns an error only when issues is non-empty.
func NewValidationError(issues []string) error {
	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Issues: append([]string(nil), issues...)}
}
