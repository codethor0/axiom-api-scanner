package openapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/getkin/kin-openapi/openapi3"
)

// ExtractEndpoints loads an OpenAPI 3.x document and returns flattened endpoints.
func ExtractEndpoints(ctx context.Context, data []byte) ([]engine.Endpoint, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("load openapi: %w", err)
	}
	if doc == nil {
		return nil, fmt.Errorf("openapi document is nil")
	}
	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("validate openapi: %w", err)
	}
	if doc.Paths == nil {
		return nil, nil
	}
	var out []engine.Endpoint
	for path, pathItem := range doc.Paths.Map() {
		if pathItem == nil {
			continue
		}
		for method, op := range pathItem.Operations() {
			if op == nil {
				continue
			}
			summary := op.Summary
			if summary == "" {
				summary = op.Description
			}
			out = append(out, engine.Endpoint{
				Method:      strings.ToUpper(method),
				Path:        path,
				OperationID: op.OperationID,
				Summary:     summary,
			})
		}
	}
	return out, nil
}
