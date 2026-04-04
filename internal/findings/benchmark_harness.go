package findings

import "strings"

// Benchmark scan target_label values (fixed local harness only). Not persisted on findings.
const (
	BenchTargetLabelHTTPBinV1 = "bench-httpbin-v1-families"
	BenchTargetLabelRateStub  = "bench-rate-stub"
)

// Stable codes for the finding-quality benchmark script and operator docs.
// Scanner policy stays in interpretation_hints on each row; these codes only add
// harness scope (which fixture) and whether an outcome is scanner policy vs fixture layout artifact.
const (
	benchTargetHTTPBinV1       = "bench_target_httpbin_v1"
	benchTargetRateStub        = "bench_target_rate_stub"
	benchScannerConfirmed      = "bench_scanner_confirmed_useful_signal"
	benchScannerTentativeWeak  = "bench_scanner_tentative_weak_similarity_policy"
	benchLayoutHttpbinOpenAPI  = "bench_fixture_layout_httpbin_openapi_operations"
	benchArtifactStubPathnorm  = "bench_fixture_artifact_pathnorm_on_single_stub_route"
	benchContextStubRateHeader = "bench_fixture_context_rate_stub_header_differential"
	benchContextHttpbinMass    = "bench_fixture_context_httpbin_post_mass_assignment"
	benchNoFindingAbsentRow    = "bench_no_finding_absent_row"
	benchNoFindingRateHttpbin  = "bench_fixture_limit_httpbin_rate_header_matcher_unsatisfied"
)

// BenchmarkHarnessRowNotes returns machine-readable codes for benchmark logs and docs.
// It must not be written to findings: use only InterpretationHints + assessment_notes there.
// targetLabel must be a known BenchTargetLabel*; otherwise returns nil.
func BenchmarkHarnessRowNotes(targetLabel, ruleID, assessmentTier string, _ []string) []string {
	label := strings.TrimSpace(targetLabel)
	var scope []string
	switch label {
	case BenchTargetLabelHTTPBinV1:
		scope = append(scope, benchTargetHTTPBinV1)
	case BenchTargetLabelRateStub:
		scope = append(scope, benchTargetRateStub)
	default:
		return nil
	}
	t := strings.ToLower(strings.TrimSpace(assessmentTier))
	rule := strings.TrimSpace(ruleID)
	switch t {
	case "confirmed":
		out := append(scope, benchScannerConfirmed)
		switch {
		case label == BenchTargetLabelRateStub && rule == "axiom.ratelimit.header_rotate.v1":
			out = append(out, benchContextStubRateHeader)
		case label == BenchTargetLabelHTTPBinV1 && rule == "axiom.mass.privilege_merge.v1":
			out = append(out, benchContextHttpbinMass)
		}
		return out
	case "tentative":
		out := append(scope, benchScannerTentativeWeak)
		switch label {
		case BenchTargetLabelHTTPBinV1:
			out = append(out, benchLayoutHttpbinOpenAPI)
		case BenchTargetLabelRateStub:
			if rule == "axiom.pathnorm.variant.v1" {
				out = append(out, benchArtifactStubPathnorm)
			}
		}
		return out
	default:
		return scope
	}
}

// BenchmarkHarnessNoFindingNotes describes an expected absent row for the httpbin scan and rate-limit rule.
func BenchmarkHarnessNoFindingNotes(targetLabel, ruleID string) []string {
	label := strings.TrimSpace(targetLabel)
	rule := strings.TrimSpace(ruleID)
	if label != BenchTargetLabelHTTPBinV1 || rule != "axiom.ratelimit.header_rotate.v1" {
		return nil
	}
	return []string{
		benchTargetHTTPBinV1,
		benchNoFindingAbsentRow,
		benchNoFindingRateHttpbin,
	}
}
