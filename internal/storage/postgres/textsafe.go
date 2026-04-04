package postgres

import (
	"strings"
	"unicode/utf8"
)

// sanitizeUTF8ForPostgres normalizes strings for PostgreSQL TEXT/JSON inputs that
// reject NUL and invalid UTF-8 (common when storing raw HTTP bodies).
func sanitizeUTF8ForPostgres(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}
