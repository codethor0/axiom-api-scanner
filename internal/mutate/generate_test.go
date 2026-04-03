package mutate

import (
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
)

func TestGenerateForEndpoint_deterministicOrder(t *testing.T) {
	doc := `
id: gen.t
name: n
category: c
severity: high
confidence: high
safety:
  mode: safe
  destructive: false
target:
  methods: [GET]
  where: path
prerequisites: []
mutations:
  - kind: rotate_request_headers
    headers:
      - name: Z
        value: "1"
      - name: A
        value: "2"
  - kind: path_normalization_variant
    style: trailing_slash
matchers:
  - kind: status_code_unchanged
references: [u]
tags: []
`
	list, err := rules.ParseDocuments([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	ep := engine.ScanEndpoint{ID: "e1", PathTemplate: "/x", Method: "GET"}
	cands, err := GenerateForEndpoint(list[0], ep)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 2 {
		t.Fatal(cands)
	}
	if cands[0].Kind != rules.MutationPathNormalizationVariant {
		t.Fatalf("order: %+v", cands)
	}
}

func TestGenerateForEndpoint_rejectsUnknownKind(t *testing.T) {
	r := rules.Rule{
		ID: "x",
		Mutations: []rules.Mutation{
			{Kind: rules.MutationKind("nope")},
		},
	}
	_, err := GenerateForEndpoint(r, engine.ScanEndpoint{})
	if err == nil {
		t.Fatal("expected error")
	}
}
