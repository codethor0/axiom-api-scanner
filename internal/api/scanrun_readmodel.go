package api

import (
	"context"
	"strconv"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	v1plan "github.com/codethor0/axiom-api-scanner/internal/plan/v1"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

func filterMutatedTallies(all []engine.ExecutionRunTally) []engine.ExecutionRunTally {
	var out []engine.ExecutionRunTally
	for _, t := range all {
		if t.Phase == engine.PhaseMutated {
			out = append(out, t)
		}
	}
	return out
}

func buildScanRunReadSummary(scan engine.Scan, endpointsImported int) ScanRunReadSummary {
	return ScanRunReadSummary{
		EndpointsImported: endpointsImported,
		Baseline:          baselinePhaseCounts(scan),
		Mutation:          mutationPhaseCounts(scan),
		FindingsCreated:   scan.FindingsCount,
	}
}

func baselinePhaseCounts(scan engine.Scan) ScanRunPhaseCounts {
	st := strings.TrimSpace(scan.BaselineRunStatus)
	total := scan.BaselineEndpointsTotal
	done := scan.BaselineEndpointsDone
	skipped := 0
	if st == "succeeded" {
		if d := total - done; d > 0 {
			skipped = d
		}
	}
	return ScanRunPhaseCounts{
		RunStatus: st,
		Total:     total,
		Completed: done,
		Skipped:   skipped,
	}
}

func mutationPhaseCounts(scan engine.Scan) ScanRunPhaseCounts {
	st := strings.TrimSpace(scan.MutationRunStatus)
	total := scan.MutationCandidatesTotal
	done := scan.MutationCandidatesDone
	skipped := 0
	if st == "succeeded" {
		if d := total - done; d > 0 {
			skipped = d
		}
	}
	return ScanRunPhaseCounts{
		RunStatus: st,
		Total:     total,
		Completed: done,
		Skipped:   skipped,
	}
}

func buildScanFindingsSummary(ctx context.Context, repo storage.FindingRepository, scanID string) (ScanFindingsSummary, error) {
	if repo == nil {
		return ScanFindingsSummary{}, nil
	}
	sum, err := repo.SummarizeFindingsForScan(ctx, scanID)
	if err != nil {
		return ScanFindingsSummary{}, err
	}
	return ScanFindingsSummary{
		Total:            sum.Total,
		ByAssessmentTier: sum.ByAssessmentTier,
		BySeverity:       sum.BySeverity,
	}, nil
}

// familyKey identifies one of the four stable V1 mutation families surfaced on the run status API.
type familyKey int

const (
	familyIDOR familyKey = iota
	familyMassAssignment
	familyPathNormalization
	familyRateLimitHeaders
)

func ruleFamilies(rule rules.Rule) map[familyKey]struct{} {
	out := map[familyKey]struct{}{}
	for _, m := range rule.Mutations {
		switch m.Kind {
		case rules.MutationReplacePathParam, rules.MutationReplaceQueryParam:
			out[familyIDOR] = struct{}{}
		case rules.MutationMergeJSONFields:
			out[familyMassAssignment] = struct{}{}
		case rules.MutationPathNormalizationVariant:
			out[familyPathNormalization] = struct{}{}
		case rules.MutationRotateRequestHeaders:
			out[familyRateLimitHeaders] = struct{}{}
		}
	}
	return out
}

func rulesForFamily(rulesList []rules.Rule, fk familyKey) []rules.Rule {
	var out []rules.Rule
	for _, r := range rulesList {
		if _, ok := ruleFamilies(r)[fk]; ok {
			out = append(out, r)
		}
	}
	return out
}

func countEligibleEndpointsForFamily(endpoints []engine.ScanEndpoint, rulesForFam []rules.Rule) int {
	if len(rulesForFam) == 0 {
		return 0
	}
	n := 0
	for _, ep := range endpoints {
		for _, d := range v1plan.Plan(ep, rulesForFam) {
			if d.Eligible {
				n++
				break
			}
		}
	}
	return n
}

func countEndpointsDeclaringSecurity(endpoints []engine.ScanEndpoint) int {
	n := 0
	for _, ep := range endpoints {
		if endpointDeclaresOpenAPISecurity(ep) {
			n++
		}
	}
	return n
}

func buildScanRunRuleFamilyCoverage(scan engine.Scan, rulesList []rules.Rule, mutated []engine.ExecutionRunTally, endpoints []engine.ScanEndpoint, authConfigured bool) ScanRunRuleFamilyCoverage {
	ruleByID := make(map[string]rules.Rule, len(rulesList))
	for i := range rulesList {
		rid := strings.TrimSpace(rulesList[i].ID)
		if rid != "" {
			ruleByID[rid] = rulesList[i]
		}
	}
	rulesInPack := make(map[familyKey]int)
	for _, r := range rulesList {
		for fk := range ruleFamilies(r) {
			rulesInPack[fk]++
		}
	}
	mutCount := make(map[familyKey]int)
	for _, ex := range mutated {
		if ex.Phase != engine.PhaseMutated {
			continue
		}
		rid := strings.TrimSpace(ex.RuleID)
		r, ok := ruleByID[rid]
		if !ok {
			continue
		}
		for fk := range ruleFamilies(r) {
			mutCount[fk]++
		}
	}
	secN := countEndpointsDeclaringSecurity(endpoints)
	out := ScanRunRuleFamilyCoverage{
		IDORPathOrQuery: familyEntry(scan, rulesInPack[familyIDOR], mutCount[familyIDOR],
			countEligibleEndpointsForFamily(endpoints, rulesForFamily(rulesList, familyIDOR)), secN, authConfigured),
		MassAssignment: familyEntry(scan, rulesInPack[familyMassAssignment], mutCount[familyMassAssignment],
			countEligibleEndpointsForFamily(endpoints, rulesForFamily(rulesList, familyMassAssignment)), secN, authConfigured),
		PathNormalization: familyEntry(scan, rulesInPack[familyPathNormalization], mutCount[familyPathNormalization],
			countEligibleEndpointsForFamily(endpoints, rulesForFamily(rulesList, familyPathNormalization)), secN, authConfigured),
		RateLimitHeaders: familyEntry(scan, rulesInPack[familyRateLimitHeaders], mutCount[familyRateLimitHeaders],
			countEligibleEndpointsForFamily(endpoints, rulesForFamily(rulesList, familyRateLimitHeaders)), secN, authConfigured),
	}
	return out
}

func groundedFamilyContributors(primaryCode string, rulesInPack, eligibleEndpoints, secEndpoints int, authConfigured bool) []ScanRunDiagnosticLine {
	var out []ScanRunDiagnosticLine
	if rulesInPack > 0 && eligibleEndpoints == 0 && primaryCode != "no_rules_for_family_in_pack" {
		out = append(out, ScanRunDiagnosticLine{
			Code:   "no_eligible_imported_endpoints_for_family",
			Detail: "V1 planner found no eligible imported operation for any loaded rule in this family",
		})
	}
	if !authConfigured && secEndpoints > 0 {
		out = append(out, ScanRunDiagnosticLine{
			Code:   "declared_secure_openapi_operations_present_auth_headers_absent",
			Detail: strconv.Itoa(secEndpoints) + " imported operation(s) declare OpenAPI security schemes; scan has no auth_headers (outbound requests omit configured credentials)",
		})
	}
	return out
}

func familyEntry(scan engine.Scan, rulesInPack, mutN, eligibleEndpoints, secEndpoints int, authConfigured bool) ScanRunFamilyCoverageEntry {
	exercised := mutN > 0
	e := ScanRunFamilyCoverageEntry{
		Exercised:         exercised,
		RulesInPack:       rulesInPack,
		MutatedExecutions: mutN,
	}
	if exercised {
		return e
	}
	var reason ScanRunDiagnosticLine
	var primaryCode string
	switch {
	case rulesInPack == 0:
		primaryCode = "no_rules_for_family_in_pack"
		reason = ScanRunDiagnosticLine{
			Code:   primaryCode,
			Detail: "no loaded rules under AXIOM_RULES_DIR include this mutation family",
		}
	case strings.TrimSpace(scan.MutationRunStatus) != "succeeded":
		primaryCode = "mutation_pass_not_succeeded"
		reason = ScanRunDiagnosticLine{
			Code:   primaryCode,
			Detail: "mutation_run_status is \"" + strings.TrimSpace(scan.MutationRunStatus) + "\" on the scan row",
		}
	case scan.MutationCandidatesTotal == 0:
		primaryCode = "zero_mutation_candidates_total"
		reason = ScanRunDiagnosticLine{
			Code:   primaryCode,
			Detail: "mutation_candidates_total is 0 on the scan row",
		}
	default:
		primaryCode = "no_mutated_executions_for_family"
		reason = ScanRunDiagnosticLine{
			Code:   primaryCode,
			Detail: "no execution_records with phase mutated for rules using this family (see /v1/scans/{scan_id}/executions?phase=mutated)",
		}
	}
	e.NotExercisedReason = &reason
	e.NotExercisedContributors = groundedFamilyContributors(primaryCode, rulesInPack, eligibleEndpoints, secEndpoints, authConfigured)
	return e
}

func scanRuleFamilyCoverageRulesDirMissing() ScanRunRuleFamilyCoverage {
	line := ScanRunDiagnosticLine{
		Code:   "rules_dir_not_configured",
		Detail: "API handler has no rules directory; load rules via AXIOM_RULES_DIR to compute family coverage",
	}
	return ScanRunRuleFamilyCoverage{
		UnavailableReason: &line,
		IDORPathOrQuery: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{
				Code:   "rule_family_coverage_unavailable",
				Detail: line.Detail,
			},
		},
		MassAssignment: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{
				Code:   "rule_family_coverage_unavailable",
				Detail: line.Detail,
			},
		},
		PathNormalization: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{
				Code:   "rule_family_coverage_unavailable",
				Detail: line.Detail,
			},
		},
		RateLimitHeaders: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{
				Code:   "rule_family_coverage_unavailable",
				Detail: line.Detail,
			},
		},
	}
}

func scanRuleFamilyCoverageExecutionsUnavailable() ScanRunRuleFamilyCoverage {
	line := ScanRunDiagnosticLine{
		Code:   "executions_repository_unavailable",
		Detail: "persistence has no execution repository; cannot join mutated rows to rules",
	}
	return ScanRunRuleFamilyCoverage{
		UnavailableReason: &line,
		IDORPathOrQuery: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{Code: "rule_family_coverage_unavailable", Detail: line.Detail},
		},
		MassAssignment: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{Code: "rule_family_coverage_unavailable", Detail: line.Detail},
		},
		PathNormalization: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{Code: "rule_family_coverage_unavailable", Detail: line.Detail},
		},
		RateLimitHeaders: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{Code: "rule_family_coverage_unavailable", Detail: line.Detail},
		},
	}
}

func scanRuleFamilyCoverageRulesLoadFailed(err error) ScanRunRuleFamilyCoverage {
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		msg = "unknown error"
	}
	line := ScanRunDiagnosticLine{
		Code:   "rules_load_failed",
		Detail: msg,
	}
	return ScanRunRuleFamilyCoverage{
		UnavailableReason: &line,
		IDORPathOrQuery: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{Code: "rules_load_failed", Detail: msg},
		},
		MassAssignment: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{Code: "rules_load_failed", Detail: msg},
		},
		PathNormalization: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{Code: "rules_load_failed", Detail: msg},
		},
		RateLimitHeaders: ScanRunFamilyCoverageEntry{
			NotExercisedReason: &ScanRunDiagnosticLine{Code: "rules_load_failed", Detail: msg},
		},
	}
}

func buildScanRunGuidance(scan engine.Scan, endpointsN, secEndpoints int, authConfigured bool) ScanRunGuidance {
	steps := make([]ScanRunDiagnosticLine, 0, 6)
	if endpointsN == 0 {
		steps = append(steps, ScanRunDiagnosticLine{
			Code:   "import_openapi_first",
			Detail: "POST /v1/scans/{scan_id}/specs/openapi with the target OpenAPI document before baseline or orchestration",
		})
	}
	if secEndpoints > 0 && !authConfigured {
		steps = append(steps, ScanRunDiagnosticLine{
			Code:   "configure_auth_headers",
			Detail: "PATCH /v1/scans/{scan_id} with replace_auth_headers and auth_headers so operations that declare security can be exercised",
		})
	}
	if scan.BaselineRunStatus == "failed" {
		steps = append(steps, ScanRunDiagnosticLine{
			Code:   "resume_after_baseline_failure",
			Detail: "address baseline_run_error, then POST /v1/scans/{scan_id}/run with {\"action\":\"resume\"}",
		})
	}
	if scan.MutationRunStatus == "failed" {
		steps = append(steps, ScanRunDiagnosticLine{
			Code:   "resume_after_mutation_failure",
			Detail: "address mutation_run_error, then POST /v1/scans/{scan_id}/run with {\"action\":\"resume\"}",
		})
	}
	if scan.RunPhase == engine.PhaseFailed {
		steps = append(steps, ScanRunDiagnosticLine{
			Code:   "resume_orchestrated_run",
			Detail: "POST /v1/scans/{scan_id}/run with {\"action\":\"resume\"} after addressing orchestrator_error (sync-only; call blocks until completion)",
		})
	}
	if scan.MutationRunStatus == "succeeded" && scan.MutationCandidatesTotal == 0 &&
		(scan.RunPhase == engine.PhaseFindingsComplete || scan.RunPhase == engine.PhaseMutationComplete) {
		steps = append(steps, ScanRunDiagnosticLine{
			Code:   "no_eligible_mutation_candidates",
			Detail: "mutation completed with mutation_candidates_total 0 for current rules and imported endpoints",
		})
	}
	return ScanRunGuidance{NextSteps: steps}
}

// findingsSummaryFromList builds tier/severity maps without a second store roundtrip (tests / call sites with data in memory).
func findingsSummaryFromList(list []findings.Finding) ScanFindingsSummary {
	out := ScanFindingsSummary{
		Total:            len(list),
		ByAssessmentTier: map[string]int{},
		BySeverity:       map[string]int{},
	}
	for _, f := range list {
		tier := strings.TrimSpace(f.AssessmentTier)
		if tier != "" {
			out.ByAssessmentTier[tier]++
		}
		sev := strings.TrimSpace(string(f.Severity))
		if sev != "" {
			out.BySeverity[sev]++
		}
	}
	if len(out.ByAssessmentTier) == 0 {
		out.ByAssessmentTier = nil
	}
	if len(out.BySeverity) == 0 {
		out.BySeverity = nil
	}
	return out
}
