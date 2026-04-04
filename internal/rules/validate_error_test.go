package rules

import (
	"errors"
	"strings"
	"testing"
)

func TestValidationError_format(t *testing.T) {
	err := NewValidationError([]string{"first issue", "second issue"})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError wrapper")
	}
	msg := err.Error()
	if !strings.Contains(msg, "2 issues") || !strings.Contains(msg, "1. first") || !strings.Contains(msg, "2. second") {
		t.Fatal(msg)
	}
}

func TestValidationError_nilWhenNoIssues(t *testing.T) {
	if NewValidationError(nil) != nil {
		t.Fatal("expected nil")
	}
	if NewValidationError([]string{}) != nil {
		t.Fatal("expected nil")
	}
}
