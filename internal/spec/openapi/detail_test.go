package openapi

import (
	"context"
	"testing"
)

func TestExtractEndpointSpecs_orderAndJSONBody(t *testing.T) {
	const spec = `openapi: 3.0.3
info:
  title: T
  version: "1.0"
paths:
  /b:
    get:
      responses:
        "200":
          description: ok
  /a:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
      responses:
        "200":
          description: ok
`
	got, err := ExtractEndpointSpecs(context.Background(), []byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len %d %+v", len(got), got)
	}
	if got[0].Path != "/a" || got[0].Method != "POST" || !got[0].RequestBodyJSON {
		t.Fatalf("first %+v", got[0])
	}
	if got[1].Path != "/b" || got[1].Method != "GET" {
		t.Fatalf("second %+v", got[1])
	}
}

func TestExtractEndpointSpecs_pathParameterMustBeDeclared(t *testing.T) {
	const spec = `openapi: 3.0.3
info:
  title: T
  version: "1.0"
paths:
  /anything/{id}:
    get:
      responses:
        "200":
          description: ok
`
	_, err := ExtractEndpointSpecs(context.Background(), []byte(spec))
	if err == nil {
		t.Fatal("expected validation error for path parameter without declaration")
	}
}
