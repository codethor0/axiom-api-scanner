package findings

import "testing"

func TestBenchmarkRuleFamilyKey(t *testing.T) {
	if g, w := BenchmarkRuleFamilyKey("axiom.idor.path_swap.v1"), "idor_path_or_query_swap"; g != w {
		t.Fatalf("%q", g)
	}
	if g, w := BenchmarkRuleFamilyKey("axiom.ratelimit.header_rotate.v1"), "rate_limit_header_rotation"; g != w {
		t.Fatalf("%q", g)
	}
	if BenchmarkRuleFamilyKey("nope") != "unknown_rule_family" {
		t.Fatal()
	}
}

func TestBenchmarkOutcomeClass_fixtureLimitedRateOnHttpbin(t *testing.T) {
	if g, w := BenchmarkOutcomeClass(BenchTargetLabelHTTPBinV1, "axiom.ratelimit.header_rotate.v1", "", 0), BenchOutcomeFixtureLimitedNoRow; g != w {
		t.Fatalf("%q want %q", g, w)
	}
}

func TestBenchmarkOutcomeClass_notExercisedIdorOnStub(t *testing.T) {
	if g, w := BenchmarkOutcomeClass(BenchTargetLabelRateStub, "axiom.idor.path_swap.v1", "", 0), BenchOutcomeNotExercisedOnTarget; g != w {
		t.Fatalf("%q want %q", g, w)
	}
}

func TestBenchmarkOutcomeClass_confirmedAndTentative(t *testing.T) {
	if g := BenchmarkOutcomeClass(BenchTargetLabelHTTPBinV1, "axiom.mass.privilege_merge.v1", "confirmed", 1); g != BenchOutcomeConfirmedUseful {
		t.Fatalf("%q", g)
	}
	if g := BenchmarkOutcomeClass(BenchTargetLabelHTTPBinV1, "axiom.pathnorm.variant.v1", "tentative", 2); g != BenchOutcomeTentativeWeakSignal {
		t.Fatalf("%q", g)
	}
}
