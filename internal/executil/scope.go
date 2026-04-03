package executil

import (
	"net/url"
	"strings"
)

// JoinScanURL joins an absolute base URL with a path segment for outgoing requests.
func JoinScanURL(baseStr, path string) (string, error) {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		path = "/"
	}
	return url.JoinPath(strings.TrimSuffix(baseStr, "/"), path)
}

// HasPrefixURL reports whether fullURL is under baseStr (same origin path prefix).
func HasPrefixURL(baseStr, full string) bool {
	baseStr = strings.TrimSuffix(baseStr, "/")
	full = strings.TrimSuffix(full, "/")
	return strings.HasPrefix(full, baseStr)
}

// JoinRawBaseURLToPath appends a path to the scan base without normalizing percent-encoded segments.
// Use for mutation paths where JoinScanURL might collapse encodings such as %2F.
func JoinRawBaseURLToPath(baseStr, path string) string {
	path = strings.TrimPrefix(path, "/")
	return strings.TrimSuffix(baseStr, "/") + "/" + path
}
