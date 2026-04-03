package executil

import (
	"net/http"
	"testing"
)

func TestRedactSensitiveHeaders_stripsAuthorizationLikeValues(t *testing.T) {
	out := RedactSensitiveHeaders(FilterHeaders(http.Header{
		"Authorization": []string{"Bearer secret"},
		"X-Custom":      []string{"visible"},
	}))
	if out["Authorization"] != "[REDACTED]" {
		t.Fatalf("%q", out["Authorization"])
	}
	if out["X-Custom"] != "visible" {
		t.Fatal(out)
	}
}
