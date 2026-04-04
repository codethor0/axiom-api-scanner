package findings

import (
	"reflect"
	"testing"
)

func TestBenchmarkHarnessRowNotes_httpbin_tentative_pathnorm(t *testing.T) {
	notes := []string{"weak_body_similarity_matcher", "similarity_min_score_0.85"}
	got := BenchmarkHarnessRowNotes(BenchTargetLabelHTTPBinV1, "axiom.pathnorm.variant.v1", "tentative", notes)
	want := []string{
		benchTargetHTTPBinV1,
		benchScannerTentativeWeak,
		benchLayoutHttpbinOpenAPI,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestBenchmarkHarnessRowNotes_rate_stub_tentative_pathnorm_fixture_artifact(t *testing.T) {
	notes := []string{"weak_body_similarity_matcher", "similarity_min_score_0.85"}
	got := BenchmarkHarnessRowNotes(BenchTargetLabelRateStub, "axiom.pathnorm.variant.v1", "tentative", notes)
	want := []string{
		benchTargetRateStub,
		benchScannerTentativeWeak,
		benchArtifactStubPathnorm,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestBenchmarkHarnessRowNotes_httpbin_confirmed_mass(t *testing.T) {
	got := BenchmarkHarnessRowNotes(BenchTargetLabelHTTPBinV1, "axiom.mass.privilege_merge.v1", "confirmed", nil)
	want := []string{
		benchTargetHTTPBinV1,
		benchScannerConfirmed,
		benchContextHttpbinMass,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestBenchmarkHarnessRowNotes_rate_stub_confirmed_rate(t *testing.T) {
	got := BenchmarkHarnessRowNotes(BenchTargetLabelRateStub, "axiom.ratelimit.header_rotate.v1", "confirmed", nil)
	want := []string{
		benchTargetRateStub,
		benchScannerConfirmed,
		benchContextStubRateHeader,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestBenchmarkHarnessNoFindingNotes_rate_on_httpbin(t *testing.T) {
	got := BenchmarkHarnessNoFindingNotes(BenchTargetLabelHTTPBinV1, "axiom.ratelimit.header_rotate.v1")
	want := []string{
		benchTargetHTTPBinV1,
		benchNoFindingAbsentRow,
		benchNoFindingRateHttpbin,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestBenchmarkHarnessRowNotes_httpbin_tentative_idor(t *testing.T) {
	notes := []string{"weak_body_similarity_matcher", "similarity_min_score_0.85"}
	got := BenchmarkHarnessRowNotes(BenchTargetLabelHTTPBinV1, "axiom.idor.path_swap.v1", "tentative", notes)
	want := []string{
		benchTargetHTTPBinV1,
		benchScannerTentativeWeak,
		benchLayoutHttpbinOpenAPI,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestBenchmarkHarnessNoFindingNotes_other_returns_nil(t *testing.T) {
	if got := BenchmarkHarnessNoFindingNotes(BenchTargetLabelRateStub, "axiom.ratelimit.header_rotate.v1"); got != nil {
		t.Fatalf("%v", got)
	}
	if got := BenchmarkHarnessRowNotes("unknown-label", "axiom.pathnorm.variant.v1", "tentative", []string{"weak_body_similarity_matcher"}); got != nil {
		t.Fatalf("%v", got)
	}
}
