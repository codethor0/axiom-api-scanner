package executil

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// NormalizeResponseBody mirrors baseline evidence normalization for diffing.
func NormalizeResponseBody(ct string, b []byte) string {
	ctLower := strings.ToLower(ct)
	if strings.Contains(ctLower, "application/json") && len(b) > 0 {
		var buf bytes.Buffer
		if err := json.Compact(&buf, b); err == nil {
			return toValidUTF8Text(buf.String())
		}
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 65536 {
		s = s[:65536]
	}
	return toValidUTF8Text(s)
}

func toValidUTF8Text(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}
