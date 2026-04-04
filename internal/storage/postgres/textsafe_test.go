package postgres

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeUTF8ForPostgres_nullAndInvalidUTF8(t *testing.T) {
	in := "a\x00b\xff\xfe"
	got := sanitizeUTF8ForPostgres(in)
	if strings.Contains(got, "\x00") {
		t.Fatal("NUL must be stripped")
	}
	if !utf8.ValidString(got) {
		t.Fatalf("got %q", got)
	}
}
