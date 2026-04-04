package openapi

import (
	"context"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

// ExtractEndpoints loads an OpenAPI 3.x document and returns flattened endpoints.
func ExtractEndpoints(ctx context.Context, data []byte) ([]engine.Endpoint, error) {
	specs, err := ExtractEndpointSpecs(ctx, data)
	if err != nil {
		return nil, err
	}
	out := make([]engine.Endpoint, len(specs))
	for i := range specs {
		out[i] = engine.Endpoint{
			Method:      specs[i].Method,
			Path:        specs[i].Path,
			OperationID: specs[i].OperationID,
			Summary:     specs[i].Summary,
		}
	}
	return out, nil
}
