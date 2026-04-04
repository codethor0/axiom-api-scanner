package openapi

import (
	"github.com/getkin/kin-openapi/openapi3"
)

// stripSchemaExamples clears Example on schemas and parameters so kin-openapi
// validation can succeed for widely published specs (e.g. OWASP crAPI) that use
// string literals where numeric examples are required. Axiom does not use
// schema examples for endpoint discovery.
func stripSchemaExamples(doc *openapi3.T) {
	if doc == nil {
		return
	}
	if doc.Components != nil {
		if doc.Components.Schemas != nil {
			for _, ref := range doc.Components.Schemas {
				if ref != nil {
					clearSchemaRef(ref)
				}
			}
		}
		if doc.Components.Parameters != nil {
			for _, ref := range doc.Components.Parameters {
				if ref != nil {
					clearParameter(ref.Value)
				}
			}
		}
		if doc.Components.RequestBodies != nil {
			for _, ref := range doc.Components.RequestBodies {
				if ref != nil {
					clearRequestBody(ref.Value)
				}
			}
		}
		if doc.Components.Responses != nil {
			for _, ref := range doc.Components.Responses {
				if ref != nil {
					clearResponse(ref.Value)
				}
			}
		}
		if doc.Components.Headers != nil {
			for _, ref := range doc.Components.Headers {
				if ref != nil {
					clearHeader(ref.Value)
				}
			}
		}
	}
	if doc.Paths == nil {
		return
	}
	for _, item := range doc.Paths.Map() {
		if item == nil {
			continue
		}
		for _, op := range item.Operations() {
			clearOperation(op)
		}
		for _, pref := range item.Parameters {
			if pref != nil {
				clearParameter(pref.Value)
			}
		}
	}
}

func clearOperation(op *openapi3.Operation) {
	if op == nil {
		return
	}
	for _, pref := range op.Parameters {
		if pref != nil {
			clearParameter(pref.Value)
		}
	}
	if op.RequestBody != nil {
		clearRequestBody(op.RequestBody.Value)
	}
	if op.Responses != nil {
		for _, respRef := range op.Responses.Map() {
			clearResponse(respRef.Value)
		}
	}
}

func clearRequestBody(rb *openapi3.RequestBody) {
	if rb == nil {
		return
	}
	for _, mt := range rb.Content {
		if mt != nil {
			clearSchemaRef(mt.Schema)
		}
	}
}

func clearResponse(resp *openapi3.Response) {
	if resp == nil {
		return
	}
	for _, mt := range resp.Content {
		if mt != nil {
			clearSchemaRef(mt.Schema)
		}
	}
	for _, hRef := range resp.Headers {
		clearHeader(hRef.Value)
	}
}

func clearHeader(h *openapi3.Header) {
	if h == nil {
		return
	}
	clearSchemaRef(h.Schema)
}

func clearParameter(p *openapi3.Parameter) {
	if p == nil {
		return
	}
	p.Example = nil
	p.Examples = nil
	for _, mt := range p.Content {
		if mt != nil {
			clearSchemaRef(mt.Schema)
		}
	}
	clearSchemaRef(p.Schema)
}

func clearSchemaRef(ref *openapi3.SchemaRef) {
	if ref == nil || ref.Value == nil {
		return
	}
	clearSchema(ref.Value)
}

func clearSchema(s *openapi3.Schema) {
	if s == nil {
		return
	}
	s.Example = nil
	for _, ref := range s.OneOf {
		clearSchemaRef(ref)
	}
	for _, ref := range s.AnyOf {
		clearSchemaRef(ref)
	}
	for _, ref := range s.AllOf {
		clearSchemaRef(ref)
	}
	clearSchemaRef(s.Not)
	clearSchemaRef(s.Items)
	for _, ref := range s.Properties {
		clearSchemaRef(ref)
	}
	ap := s.AdditionalProperties.Schema
	if ap != nil {
		clearSchemaRef(ap)
	}
}
