package openapi

import (
	"context"
	"testing"

	"github.com/chomechomekitchen/axiom-api-scanner/internal/engine"
)

func TestExtractEndpoints_minimal(t *testing.T) {
	const spec = `
openapi: 3.0.3
info:
  title: T
  version: "1.0"
paths:
  /items/{id}:
    get:
      operationId: getItem
      summary: Get item
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
`
	got, err := ExtractEndpoints(context.Background(), []byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d %+v", len(got), got)
	}
	want := engine.Endpoint{Method: "GET", Path: "/items/{id}", OperationID: "getItem", Summary: "Get item"}
	if got[0] != want {
		t.Fatalf("got %+v want %+v", got[0], want)
	}
}

func TestExtractEndpoints_invalid(t *testing.T) {
	_, err := ExtractEndpoints(context.Background(), []byte("not: openapi"))
	if err == nil {
		t.Fatal("expected error")
	}
}
