package openapi

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/getkin/kin-openapi/openapi3"
)

var methodOrder = map[string]int{
	"GET":     0,
	"HEAD":    1,
	"POST":    2,
	"PUT":     3,
	"PATCH":   4,
	"DELETE":  5,
	"OPTIONS": 6,
	"TRACE":   7,
}

// ExtractEndpointSpecs validates OpenAPI and returns deterministic ordered endpoint rows for import.
func ExtractEndpointSpecs(ctx context.Context, data []byte) ([]engine.EndpointSpec, error) {
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
	type pair struct {
		path   string
		method string
		op     *openapi3.Operation
	}
	var pairs []pair
	for path, item := range doc.Paths.Map() {
		if item == nil {
			continue
		}
		for method, op := range item.Operations() {
			if op == nil {
				continue
			}
			pairs = append(pairs, pair{path: path, method: strings.ToUpper(method), op: op})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].path != pairs[j].path {
			return pairs[i].path < pairs[j].path
		}
		return methodRank(pairs[i].method) < methodRank(pairs[j].method)
	})
	out := make([]engine.EndpointSpec, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, buildSpec(doc, p.path, p.method, p.op))
	}
	return out, nil
}

func methodRank(m string) int {
	if r, ok := methodOrder[strings.ToUpper(m)]; ok {
		return r
	}
	return 99
}

func buildSpec(doc *openapi3.T, path, method string, op *openapi3.Operation) engine.EndpointSpec {
	summary := op.Summary
	if summary == "" {
		summary = op.Description
	}
	reqTypes, reqJSON := requestBodyMeta(op)
	respTypes := responseContentTypes(op)
	return engine.EndpointSpec{
		Method:               method,
		Path:                 path,
		OperationID:          op.OperationID,
		Summary:              summary,
		SecuritySchemeHints:  securityHints(doc, op),
		RequestContentTypes:  reqTypes,
		ResponseContentTypes: respTypes,
		RequestBodyJSON:      reqJSON,
	}
}

func securityHints(doc *openapi3.T, op *openapi3.Operation) []string {
	seen := make(map[string]struct{})
	var names []string
	addReq := func(s openapi3.SecurityRequirements) {
		for _, req := range s {
			for name := range req {
				if name == "" {
					continue
				}
				if _, ok := seen[name]; !ok {
					seen[name] = struct{}{}
					names = append(names, name)
				}
			}
		}
	}
	if op.Security != nil && len(*op.Security) > 0 {
		addReq(*op.Security)
	} else if len(doc.Security) > 0 {
		addReq(doc.Security)
	}
	sort.Strings(names)
	return names
}

func requestBodyMeta(op *openapi3.Operation) ([]string, bool) {
	if op.RequestBody == nil || op.RequestBody.Value == nil || op.RequestBody.Value.Content == nil {
		return nil, false
	}
	var types []string
	for mt := range op.RequestBody.Value.Content {
		types = append(types, mt)
	}
	sort.Strings(types)
	_, jsonMT := op.RequestBody.Value.Content["application/json"]
	return types, jsonMT
}

func responseContentTypes(op *openapi3.Operation) []string {
	if op.Responses == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, code := range []string{"200", "201", "204", "default"} {
		resp := op.Responses.Map()[code]
		if resp == nil || resp.Value == nil || resp.Value.Content == nil {
			continue
		}
		for mt := range resp.Value.Content {
			if mt == "" {
				continue
			}
			if _, ok := seen[mt]; !ok {
				seen[mt] = struct{}{}
				out = append(out, mt)
			}
		}
	}
	sort.Strings(out)
	return out
}
