package openapi

import (
	"context"
	"testing"
)

// crAPI and similar specs sometimes declare integer parameters with a quoted JSON example.
func TestExtractEndpointSpecs_stringExampleOnIntegerImports(t *testing.T) {
	const spec = `{
  "openapi": "3.0.1",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/community/api/v2/community/posts/recent": {
      "get": {
        "parameters": [
          {
            "name": "limit",
            "in": "query",
            "schema": {"type": "integer", "example": "30"}
          }
        ],
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`
	got, err := ExtractEndpointSpecs(context.Background(), []byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Method != "GET" {
		t.Fatalf("%+v", got)
	}
}
