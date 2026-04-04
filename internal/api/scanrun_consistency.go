package api

import (
	"strconv"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

// scanRunReadModelConsistencyContext carries cross-field checks for GET .../run/status (inventory, progress, summary, protected_route).
type scanRunReadModelConsistencyContext struct {
	Progress               ScanRunProgress
	Summary                ScanRunReadSummary
	Protected              ScanRunProtectedRouteCoverage
	InventoryEndpointCount int
	CoverageSecEndpoints   int
}

func inconsistentLine(code, detail string) ScanRunDiagnosticLine {
	return ScanRunDiagnosticLine{Code: code, Detail: detail, Category: ScanDiagCategoryInconsistent}
}

// scanRunConsistencyLines returns grounded diagnostics when persisted read-model fields disagree.
// It never mutates storage or repairs values; callers surface these under diagnostics.consistency_detail.
func scanRunConsistencyLines(scan engine.Scan, findingsSummary ScanFindingsSummary, findingsRepoConfigured bool, mutatedExecutionCount int, fam ScanRunRuleFamilyCoverage, ctx *scanRunReadModelConsistencyContext) []ScanRunDiagnosticLine {
	out := make([]ScanRunDiagnosticLine, 0, 6)
	if findingsRepoConfigured && findingsSummary.Total != scan.FindingsCount {
		out = append(out, inconsistentLine("findings_count_drift",
			"scans.findings_count="+strconv.Itoa(scan.FindingsCount)+
				" findings_summary.total="+strconv.Itoa(findingsSummary.Total)+" (persisted findings aggregate)"))
	}

	if ctx != nil {
		if ctx.Progress.EndpointsDiscovered != ctx.Summary.EndpointsImported {
			out = append(out, inconsistentLine("read_model_endpoints_mismatch",
				"progress.endpoints_discovered="+strconv.Itoa(ctx.Progress.EndpointsDiscovered)+
					" summary.endpoints_imported="+strconv.Itoa(ctx.Summary.EndpointsImported)))
		}
		if ctx.Progress.FindingsCreated != ctx.Summary.FindingsCreated {
			out = append(out, inconsistentLine("read_model_findings_mismatch",
				"progress.findings_created="+strconv.Itoa(ctx.Progress.FindingsCreated)+
					" summary.findings_created="+strconv.Itoa(ctx.Summary.FindingsCreated)))
		}
		bucketSum := ctx.Protected.EndpointsDeclaringSecurity + ctx.Protected.EndpointsWithoutSecurityDeclaration
		if ctx.InventoryEndpointCount >= 0 && bucketSum != ctx.InventoryEndpointCount {
			out = append(out, inconsistentLine("protected_route_endpoint_buckets_mismatch",
				"protected_route_coverage secure+public endpoints="+strconv.Itoa(bucketSum)+
					" inventory count="+strconv.Itoa(ctx.InventoryEndpointCount)))
		}
		if ctx.CoverageSecEndpoints != ctx.Protected.EndpointsDeclaringSecurity {
			out = append(out, inconsistentLine("coverage_vs_protected_secure_count_mismatch",
				"coverage.endpoints_declaring_security="+strconv.Itoa(ctx.CoverageSecEndpoints)+
					" protected_route_coverage.endpoints_declaring_security="+strconv.Itoa(ctx.Protected.EndpointsDeclaringSecurity)))
		}
		if ctx.Protected.ExecutionsRepositoryConfigured {
			mutBuckets := ctx.Protected.MutatedRecordsDeclaringSecurity + ctx.Protected.MutatedRecordsWithoutSecurityDeclaration
			if mutatedExecutionCount > mutBuckets {
				out = append(out, inconsistentLine("mutated_executions_not_classified_in_protected_route",
					"execution_records phase mutated="+strconv.Itoa(mutatedExecutionCount)+
						" tallies attributed in protected_route_coverage="+strconv.Itoa(mutBuckets)+" (orphan scan_endpoint_id or storage drift)"))
			}
		}
	}

	if scan.BaselineEndpointsTotal < 0 || scan.BaselineEndpointsDone < 0 {
		out = append(out, inconsistentLine("scan_row_negative_baseline_counter",
			"baseline_endpoints_total or baseline_endpoints_done is negative on the scan row"))
	} else if scan.BaselineEndpointsDone > scan.BaselineEndpointsTotal {
		out = append(out, inconsistentLine("baseline_progress_inconsistent",
			"baseline_endpoints_done="+strconv.Itoa(scan.BaselineEndpointsDone)+
				" baseline_endpoints_total="+strconv.Itoa(scan.BaselineEndpointsTotal)+" on scan row"))
	}
	if scan.MutationCandidatesTotal < 0 || scan.MutationCandidatesDone < 0 {
		out = append(out, inconsistentLine("scan_row_negative_mutation_counter",
			"mutation_candidates_total or mutation_candidates_done is negative on the scan row"))
	} else if scan.MutationCandidatesDone > scan.MutationCandidatesTotal {
		out = append(out, inconsistentLine("mutation_progress_inconsistent",
			"mutation_candidates_done="+strconv.Itoa(scan.MutationCandidatesDone)+
				" mutation_candidates_total="+strconv.Itoa(scan.MutationCandidatesTotal)+" on scan row"))
	}

	if fam.UnavailableReason != nil {
		return out
	}
	nMut := mutatedExecutionCount
	sumFam := fam.IDORPathOrQuery.MutatedExecutions +
		fam.MassAssignment.MutatedExecutions +
		fam.PathNormalization.MutatedExecutions +
		fam.RateLimitHeaders.MutatedExecutions
	if sumFam > nMut {
		out = append(out, inconsistentLine("family_coverage_mutated_sum_exceeds_rows",
			"sum(rule_family_coverage.*.mutated_executions)="+strconv.Itoa(sumFam)+
				" mutated execution rows="+strconv.Itoa(nMut)+" (multi-family rules or inconsistency)"))
	}
	checkFam := func(name string, n int) {
		if n > nMut {
			out = append(out, inconsistentLine("family_coverage_mutated_exceeds_rows",
				strings.TrimSpace(name)+".mutated_executions="+strconv.Itoa(n)+
					" mutated execution rows="+strconv.Itoa(nMut)))
		}
	}
	checkFam("idor_path_or_query_swap", fam.IDORPathOrQuery.MutatedExecutions)
	checkFam("mass_assignment_privilege_injection", fam.MassAssignment.MutatedExecutions)
	checkFam("path_normalization_bypass", fam.PathNormalization.MutatedExecutions)
	checkFam("rate_limit_header_rotation", fam.RateLimitHeaders.MutatedExecutions)
	return out
}
