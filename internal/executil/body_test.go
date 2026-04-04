package executil

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeResponseBody_nonUTF8BecomesReplacement(t *testing.T) {
	// gzip magic header bytes are invalid UTF-8; Postgres TEXT columns reject them.
	b := []byte{0x1f, 0x8b, 0x08, 0x00}
	got := NormalizeResponseBody("application/json", b)
	if !utf8.ValidString(got) {
		t.Fatal("output must be valid UTF-8")
	}
	if !strings.Contains(got, "\uFFFD") && got == "" {
		t.Fatalf("expected replacement or non-empty safe string, got %q", got)
	}
}
