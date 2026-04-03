package executil

import (
	"bytes"
	"encoding/json"
	"strings"
)

// NormalizeResponseBody mirrors baseline evidence normalization for diffing.
func NormalizeResponseBody(ct string, b []byte) string {
	ctLower := strings.ToLower(ct)
	if strings.Contains(ctLower, "application/json") && len(b) > 0 {
		var buf bytes.Buffer
		if err := json.Compact(&buf, b); err == nil {
			return buf.String()
		}
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 65536 {
		return s[:65536]
	}
	return s
}
