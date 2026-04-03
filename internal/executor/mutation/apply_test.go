package mutation

import (
	"strings"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/executil"
	"github.com/codethor0/axiom-api-scanner/internal/mutate"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
)

func TestBuildRequest_respectsScanBaseScope(t *testing.T) {
	ru := rules.Rule{
		ID: "r1",
		Mutations: []rules.Mutation{
			{Kind: rules.MutationReplacePathParam, ReplacePathParam: &rules.ReplacePathParamMutation{
				Param: "id", From: "self", To: "other",
			}},
		},
	}
	ep := engine.ScanEndpoint{ID: "e", Method: "GET", PathTemplate: "/v1/items/{id}"}
	cands, err := mutate.GenerateForEndpoint(ru, ep)
	if err != nil || len(cands) != 1 {
		t.Fatal(cands, err)
	}
	built, err := BuildRequest("http://127.0.0.1:9/api", ep, ru, cands[0])
	if err != nil {
		t.Fatal(err)
	}
	if !executil.HasPrefixURL("http://127.0.0.1:9/api", built.URL) {
		t.Fatalf("out of scope: %s", built.URL)
	}
	if !strings.Contains(built.URL, "other") {
		t.Fatalf("expected swapped segment in url: %s", built.URL)
	}
}

func TestBuildRequest_encodedSlashPath_staysUnderBase(t *testing.T) {
	ru := rules.Rule{
		ID: "r1",
		Mutations: []rules.Mutation{
			{Kind: rules.MutationPathNormalizationVariant, PathNormalizationVariant: &rules.PathNormalizationMutation{
				Style: "encoded_slash",
			}},
		},
	}
	ep := engine.ScanEndpoint{ID: "e", Method: "GET", PathTemplate: "/v1/items"}
	cands, err := mutate.GenerateForEndpoint(ru, ep)
	if err != nil || len(cands) != 1 {
		t.Fatal(cands, err)
	}
	built, err := BuildRequest("http://127.0.0.1:9/prefix", ep, ru, cands[0])
	if err != nil {
		t.Fatal(err)
	}
	if !executil.HasPrefixURL("http://127.0.0.1:9/prefix", built.URL) {
		t.Fatalf("scope leak: %s", built.URL)
	}
}
