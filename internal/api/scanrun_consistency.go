package api

import (
	"strconv"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

// scanRunConsistencyLines returns grounded diagnostics when persisted read-model fields disagree.
// It never mutates storage or repairs values; callers surface these under diagnostics.consistency_detail.
func scanRunConsistencyLines(scan engine.Scan, findingsSummary ScanFindingsSummary, findingsRepoConfigured bool, mutated []engine.ExecutionRecord, fam ScanRunRuleFamilyCoverage) []ScanRunDiagnosticLine {
	out := make([]ScanRunDiagnosticLine, 0, 4)
	if findingsRepoConfigured && findingsSummary.Total != scan.FindingsCount {
		out = append(out, ScanRunDiagnosticLine{
			Code: "findings_count_drift",
			Detail: "scans.findings_count is " + strconv.Itoa(scan.FindingsCount) +
				" but findings_summary.total from ListByScanID is " + strconv.Itoa(findingsSummary.Total),
		})
	}
	if scan.BaselineEndpointsTotal < 0 || scan.BaselineEndpointsDone < 0 {
		out = append(out, ScanRunDiagnosticLine{
			Code:   "scan_row_negative_baseline_counter",
			Detail: "baseline_endpoints_total or baseline_endpoints_done is negative on the scan row",
		})
	} else if scan.BaselineEndpointsDone > scan.BaselineEndpointsTotal {
		out = append(out, ScanRunDiagnosticLine{
			Code: "baseline_progress_inconsistent",
			Detail: "baseline_endpoints_done (" + strconv.Itoa(scan.BaselineEndpointsDone) +
				") exceeds baseline_endpoints_total (" + strconv.Itoa(scan.BaselineEndpointsTotal) + ") on the scan row",
		})
	}
	if scan.MutationCandidatesTotal < 0 || scan.MutationCandidatesDone < 0 {
		out = append(out, ScanRunDiagnosticLine{
			Code:   "scan_row_negative_mutation_counter",
			Detail: "mutation_candidates_total or mutation_candidates_done is negative on the scan row",
		})
	} else if scan.MutationCandidatesDone > scan.MutationCandidatesTotal {
		out = append(out, ScanRunDiagnosticLine{
			Code: "mutation_progress_inconsistent",
			Detail: "mutation_candidates_done (" + strconv.Itoa(scan.MutationCandidatesDone) +
				") exceeds mutation_candidates_total (" + strconv.Itoa(scan.MutationCandidatesTotal) + ") on the scan row",
		})
	}

	if fam.UnavailableReason != nil {
		return out
	}
	nMut := len(mutated)
	sumFam := fam.IDORPathOrQuery.MutatedExecutions +
		fam.MassAssignment.MutatedExecutions +
		fam.PathNormalization.MutatedExecutions +
		fam.RateLimitHeaders.MutatedExecutions
	if sumFam > nMut {
		out = append(out, ScanRunDiagnosticLine{
			Code: "family_coverage_mutated_sum_exceeds_rows",
			Detail: "sum of rule_family_coverage.*.mutated_executions (" + strconv.Itoa(sumFam) +
				") exceeds count of execution_records with phase mutated (" + strconv.Itoa(nMut) +
				") for this scan (possible multi-family rule mutations or storage inconsistency)",
		})
	}
	checkFam := func(name string, n int) {
		if n > nMut {
			out = append(out, ScanRunDiagnosticLine{
				Code: "family_coverage_mutated_exceeds_rows",
				Detail: strings.TrimSpace(name) + " mutated_executions (" + strconv.Itoa(n) +
					") exceeds execution_records with phase mutated (" + strconv.Itoa(nMut) + ")",
			})
		}
	}
	checkFam("idor_path_or_query_swap", fam.IDORPathOrQuery.MutatedExecutions)
	checkFam("mass_assignment_privilege_injection", fam.MassAssignment.MutatedExecutions)
	checkFam("path_normalization_bypass", fam.PathNormalization.MutatedExecutions)
	checkFam("rate_limit_header_rotation", fam.RateLimitHeaders.MutatedExecutions)
	return out
}
