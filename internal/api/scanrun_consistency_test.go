package api

import (
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

// UnavailableReason short-circuits family consistency checks in these tests.
var consistencySkipFamilies = ScanRunRuleFamilyCoverage{UnavailableReason: &ScanRunDiagnosticLine{Code: "x"}}

func TestScanRunConsistencyLines_findingsDrift(t *testing.T) {
	scan := engine.Scan{FindingsCount: 2}
	sum := ScanFindingsSummary{Total: 1}
	lines := scanRunConsistencyLines(scan, sum, true, 0, consistencySkipFamilies)
	if len(lines) != 1 || lines[0].Code != "findings_count_drift" {
		t.Fatalf("%+v", lines)
	}
}

func TestScanRunConsistencyLines_skipsFindingsWhenRepoNotConfigured(t *testing.T) {
	scan := engine.Scan{FindingsCount: 5}
	sum := ScanFindingsSummary{Total: 0}
	lines := scanRunConsistencyLines(scan, sum, false, 0, consistencySkipFamilies)
	for _, l := range lines {
		if l.Code == "findings_count_drift" {
			t.Fatalf("unexpected drift %+v", lines)
		}
	}
}

func TestScanRunConsistencyLines_baselineDoneExceedsTotal(t *testing.T) {
	scan := engine.Scan{BaselineEndpointsTotal: 1, BaselineEndpointsDone: 3}
	lines := scanRunConsistencyLines(scan, ScanFindingsSummary{}, false, 0, consistencySkipFamilies)
	if len(lines) != 1 || lines[0].Code != "baseline_progress_inconsistent" {
		t.Fatalf("%+v", lines)
	}
}

func TestScanRunConsistencyLines_mutationDoneExceedsTotal(t *testing.T) {
	scan := engine.Scan{MutationCandidatesTotal: 2, MutationCandidatesDone: 5}
	lines := scanRunConsistencyLines(scan, ScanFindingsSummary{}, false, 0, consistencySkipFamilies)
	if len(lines) != 1 || lines[0].Code != "mutation_progress_inconsistent" {
		t.Fatalf("%+v", lines)
	}
}

func TestScanRunConsistencyLines_familySumExceedsMutatedRows(t *testing.T) {
	fam := ScanRunRuleFamilyCoverage{
		IDORPathOrQuery: ScanRunFamilyCoverageEntry{MutatedExecutions: 2},
		MassAssignment:  ScanRunFamilyCoverageEntry{MutatedExecutions: 2},
	}
	lines := scanRunConsistencyLines(engine.Scan{}, ScanFindingsSummary{}, false, 2, fam)
	found := false
	for _, l := range lines {
		if l.Code == "family_coverage_mutated_sum_exceeds_rows" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want family sum diagnostic, got %+v", lines)
	}
}

func TestScanRunConsistencyLines_perFamilyExceedsRows(t *testing.T) {
	fam := ScanRunRuleFamilyCoverage{
		IDORPathOrQuery: ScanRunFamilyCoverageEntry{MutatedExecutions: 5},
	}
	lines := scanRunConsistencyLines(engine.Scan{}, ScanFindingsSummary{}, false, 1, fam)
	found := false
	for _, l := range lines {
		if l.Code == "family_coverage_mutated_exceeds_rows" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want per-family diagnostic, got %+v", lines)
	}
}
