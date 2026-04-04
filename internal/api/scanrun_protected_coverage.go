package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

func endpointDeclaresOpenAPISecurity(ep engine.ScanEndpoint) bool {
	return len(ep.SecuritySchemeHints) > 0
}

func endpointInBaselineRunnerScope(ep engine.ScanEndpoint) bool {
	m := strings.ToUpper(strings.TrimSpace(ep.Method))
	switch m {
	case http.MethodGet:
		return true
	case http.MethodPost:
		return ep.RequestBodyJSON
	default:
		return false
	}
}

func buildScanRunProtectedRouteCoverage(endpoints []engine.ScanEndpoint, allExec []engine.ExecutionRunTally, execRepo bool) ScanRunProtectedRouteCoverage {
	out := ScanRunProtectedRouteCoverage{ExecutionsRepositoryConfigured: execRepo}
	epByID := make(map[string]engine.ScanEndpoint, len(endpoints))
	for _, ep := range endpoints {
		epByID[ep.ID] = ep
		if endpointDeclaresOpenAPISecurity(ep) {
			out.EndpointsDeclaringSecurity++
			if endpointInBaselineRunnerScope(ep) {
				out.DeclaredSecurityInBaselineScopeEndpoints++
			}
		} else {
			out.EndpointsWithoutSecurityDeclaration++
		}
	}
	if !execRepo {
		return out
	}
	for _, ex := range allExec {
		eid := strings.TrimSpace(ex.ScanEndpointID)
		ep, ok := epByID[eid]
		if !ok {
			continue
		}
		sec := endpointDeclaresOpenAPISecurity(ep)
		switch ex.Phase {
		case engine.PhaseBaseline:
			if sec {
				out.BaselineRecordsDeclaringSecurity++
				switch {
				case ex.ResponseStatus == 401:
					out.DeclaredSecureBaselineRecordsHTTP401++
				case ex.ResponseStatus == 403:
					out.DeclaredSecureBaselineRecordsHTTP403++
				case ex.ResponseStatus >= 200 && ex.ResponseStatus <= 299:
					out.DeclaredSecureBaselineRecordsHTTP2xx++
				}
			} else {
				out.BaselineRecordsWithoutSecurityDeclaration++
			}
		case engine.PhaseMutated:
			if sec {
				out.MutatedRecordsDeclaringSecurity++
			} else {
				out.MutatedRecordsWithoutSecurityDeclaration++
			}
		}
	}
	return out
}

// appendAuthAndRouteDiagnostics adds factual skipped lines from scan row + protected_route tallies (no causes beyond persisted facts).
func appendAuthAndRouteDiagnostics(d *ScanRunDiagnostics, scan engine.Scan, authHeadersConfigured bool, pr ScanRunProtectedRouteCoverage) {
	bs := strings.TrimSpace(scan.BaselineRunStatus)
	ms := strings.TrimSpace(scan.MutationRunStatus)

	if pr.ExecutionsRepositoryConfigured && bs == "succeeded" &&
		pr.EndpointsDeclaringSecurity > 0 && pr.DeclaredSecurityInBaselineScopeEndpoints == 0 {
		d.SkippedDetail = append(d.SkippedDetail, ScanRunDiagnosticLine{
			Category: ScanDiagCategorySkipped,
			Code:     "declared_secure_operations_not_in_baseline_runner_scope",
			Detail: strconv.Itoa(pr.EndpointsDeclaringSecurity) +
				" operations declare security but none are in baseline scope (GET or JSON POST with JSON body per runner)",
		})
	}

	if pr.ExecutionsRepositoryConfigured &&
		pr.DeclaredSecurityInBaselineScopeEndpoints > 0 &&
		pr.BaselineRecordsDeclaringSecurity == 0 && bs == "succeeded" {
		d.SkippedDetail = append(d.SkippedDetail, ScanRunDiagnosticLine{
			Category: ScanDiagCategorySkipped,
			Code:     "declared_secure_baseline_scope_without_recorded_baseline_http",
			Detail: strconv.Itoa(pr.DeclaredSecurityInBaselineScopeEndpoints) +
				" in-scope secure operations but no baseline execution_record links those scan_endpoint IDs",
		})
	}

	if pr.ExecutionsRepositoryConfigured && bs == "succeeded" &&
		pr.BaselineRecordsDeclaringSecurity > 0 &&
		pr.DeclaredSecureBaselineRecordsHTTP2xx == 0 &&
		(pr.DeclaredSecureBaselineRecordsHTTP401 > 0 || pr.DeclaredSecureBaselineRecordsHTTP403 > 0) {
		code := "declared_secure_baseline_responses_only_401_or_403"
		cat := ScanDiagCategorySkipped
		if !authHeadersConfigured {
			code = "declared_secure_baseline_without_auth_headers_only_401_or_403"
			cat = ScanDiagCategoryAuthLimit
		}
		d.SkippedDetail = append(d.SkippedDetail, ScanRunDiagnosticLine{
			Category: cat,
			Code:     code,
			Detail: "declared-secure baseline HTTP: 401=" + strconv.Itoa(pr.DeclaredSecureBaselineRecordsHTTP401) +
				" 403=" + strconv.Itoa(pr.DeclaredSecureBaselineRecordsHTTP403) +
				" 2xx=" + strconv.Itoa(pr.DeclaredSecureBaselineRecordsHTTP2xx),
		})
	}

	if pr.ExecutionsRepositoryConfigured && ms == "succeeded" && scan.MutationCandidatesTotal > 0 &&
		pr.EndpointsDeclaringSecurity > 0 && pr.MutatedRecordsDeclaringSecurity == 0 {
		d.SkippedDetail = append(d.SkippedDetail, ScanRunDiagnosticLine{
			Category: ScanDiagCategorySkipped,
			Code:     "mutation_http_not_recorded_for_declared_secure_endpoints",
			Detail: "mutation_candidates_total=" + strconv.Itoa(scan.MutationCandidatesTotal) +
				" but no mutated execution_record on declared-secure endpoints",
		})
	}

	if pr.ExecutionsRepositoryConfigured && ms == "succeeded" && scan.MutationCandidatesTotal > 0 &&
		pr.EndpointsWithoutSecurityDeclaration > 0 && pr.MutatedRecordsWithoutSecurityDeclaration == 0 &&
		pr.MutatedRecordsDeclaringSecurity > 0 {
		d.SkippedDetail = append(d.SkippedDetail, ScanRunDiagnosticLine{
			Category: ScanDiagCategorySkipped,
			Code:     "mutated_http_only_recorded_for_declared_secure_endpoints",
			Detail: strconv.Itoa(pr.EndpointsWithoutSecurityDeclaration) +
				" public operations but mutated rows only on declared-secure endpoints",
		})
	}
}
