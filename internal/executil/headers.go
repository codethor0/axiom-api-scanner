package executil

import (
	"net/http"
	"strings"
)

// FilterHeaders copies the first value per canonical key.
func FilterHeaders(h http.Header) map[string]string {
	out := make(map[string]string)
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		out[http.CanonicalHeaderKey(k)] = vs[0]
	}
	return out
}

var sensitiveHeaderNames = []string{
	"Authorization",
	"Proxy-Authorization",
	"Cookie",
	"Set-Cookie",
	"X-Api-Key",
	"X-API-Key",
	"Api-Key",
}

// RedactSensitiveHeaders copies headers and replaces known credential header values.
func RedactSensitiveHeaders(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		can := http.CanonicalHeaderKey(k)
		if headerNameSensitive(can) {
			if strings.TrimSpace(v) == "" {
				out[can] = v
			} else {
				out[can] = "[REDACTED]"
			}
			continue
		}
		out[can] = v
	}
	return out
}

func headerNameSensitive(can string) bool {
	for _, s := range sensitiveHeaderNames {
		if can == s {
			return true
		}
	}
	return false
}
