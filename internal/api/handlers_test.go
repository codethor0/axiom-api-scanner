package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateOpenAPI_happyPath(t *testing.T) {
	const spec = `openapi: 3.0.3
info:
  title: T
  version: "1.0"
paths:
  /ok:
    get:
      responses:
        "204":
          description: noop
`
	h := &Handler{}
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/specs/openapi/validate", bytes.NewBufferString(spec))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
