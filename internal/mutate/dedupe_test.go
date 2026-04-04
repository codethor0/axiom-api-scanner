package mutate

import (
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/rules"
)

func TestDedupeKey_stable(t *testing.T) {
	c := Candidate{
		RuleID:        "r1",
		MutationIndex: 2,
		Kind:          rules.MutationMergeJSONFields,
		Detail:        "merge json fields a,b",
		EndpointID:    "e1",
	}
	k1 := DedupeKey(c)
	k2 := DedupeKey(c)
	if k1 != k2 || k1 == "" {
		t.Fatalf("got %q %q", k1, k2)
	}
}
