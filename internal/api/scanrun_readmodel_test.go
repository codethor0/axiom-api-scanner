package api

import (
	"context"
	"reflect"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

func TestBuildScanRunReadSummary_skippedOnlyOnSucceeded(t *testing.T) {
	scan := engine.Scan{
		BaselineRunStatus:       "failed",
		BaselineEndpointsTotal:  5,
		BaselineEndpointsDone:   2,
		MutationRunStatus:       "in_progress",
		MutationCandidatesTotal: 10,
		MutationCandidatesDone:  3,
		FindingsCount:           7,
	}
	s := buildScanRunReadSummary(scan, 4)
	if s.EndpointsImported != 4 || s.FindingsCreated != 7 {
		t.Fatalf("%+v", s)
	}
	if s.Baseline.Skipped != 0 || s.Baseline.Total != 5 || s.Baseline.Completed != 2 {
		t.Fatalf("baseline %+v", s.Baseline)
	}
	if s.Mutation.Skipped != 0 || s.Mutation.Total != 10 || s.Mutation.Completed != 3 {
		t.Fatalf("mutation %+v", s.Mutation)
	}

	scan.BaselineRunStatus = "succeeded"
	scan.MutationRunStatus = "succeeded"
	s = buildScanRunReadSummary(scan, 4)
	if s.Baseline.Skipped != 3 {
		t.Fatalf("baseline skipped want 3 got %+v", s.Baseline)
	}
	if s.Mutation.Skipped != 7 {
		t.Fatalf("mutation skipped want 7 got %+v", s.Mutation)
	}
}

func TestBuildScanRunRuleFamilyCoverage_exercisedFromMutatedRows(t *testing.T) {
	scan := engine.Scan{MutationRunStatus: "succeeded", MutationCandidatesTotal: 2}
	rl := rules.Rule{
		ID: "r1",
		Mutations: rules.Mutations{
			{Kind: rules.MutationReplacePathParam},
		},
	}
	mut := []engine.ExecutionRunTally{
		{Phase: engine.PhaseMutated, RuleID: "r1"},
	}
	ep := []engine.ScanEndpoint{{ID: "e1", Method: "GET", PathTemplate: "/p/{id}"}}
	cov := buildScanRunRuleFamilyCoverage(scan, []rules.Rule{rl}, mut, ep, false)
	if !cov.IDORPathOrQuery.Exercised || cov.IDORPathOrQuery.MutatedExecutions != 1 {
		t.Fatalf("idor %+v", cov.IDORPathOrQuery)
	}
	if cov.IDORPathOrQuery.NotExercisedReason != nil {
		t.Fatal("expected no not_exercised_reason when exercised")
	}
	if cov.MassAssignment.Exercised || cov.MassAssignment.RulesInPack != 0 {
		t.Fatalf("mass %+v", cov.MassAssignment)
	}
	if cov.MassAssignment.NotExercisedReason == nil || cov.MassAssignment.NotExercisedReason.Code != "no_rules_for_family_in_pack" {
		t.Fatalf("mass assignment reason %+v", cov.MassAssignment.NotExercisedReason)
	}
}

func TestBuildScanRunRuleFamilyCoverage_zeroCandidatesReason(t *testing.T) {
	scan := engine.Scan{MutationRunStatus: "succeeded", MutationCandidatesTotal: 0}
	rl := rules.Rule{
		ID: "r1",
		Mutations: rules.Mutations{
			{Kind: rules.MutationMergeJSONFields},
		},
	}
	cov := buildScanRunRuleFamilyCoverage(scan, []rules.Rule{rl}, nil, nil, false)
	if cov.MassAssignment.Exercised {
		t.Fatal("expected not exercised")
	}
	if cov.MassAssignment.NotExercisedReason == nil || cov.MassAssignment.NotExercisedReason.Code != "zero_mutation_candidates_total" {
		t.Fatalf("got %+v", cov.MassAssignment.NotExercisedReason)
	}
}

func TestFindingsSummaryFromList_mapsTierAndSeverity(t *testing.T) {
	s := findingsSummaryFromList([]findings.Finding{
		{AssessmentTier: "confirmed", Severity: findings.SeverityHigh},
		{AssessmentTier: "confirmed", Severity: findings.SeverityHigh},
		{AssessmentTier: "tentative", Severity: findings.SeverityLow},
	})
	if s.Total != 3 || s.ByAssessmentTier["confirmed"] != 2 || s.BySeverity["high"] != 2 {
		t.Fatalf("%+v", s)
	}
}

func TestBuildScanRunRuleFamilyCoverage_notExercisedAuthContributor(t *testing.T) {
	scan := engine.Scan{MutationRunStatus: "succeeded", MutationCandidatesTotal: 0}
	rl := rules.Rule{
		ID:     "r1",
		Target: rules.RuleTarget{Methods: []string{"GET"}, Where: "path_params.id"},
		Mutations: rules.Mutations{
			{Kind: rules.MutationReplacePathParam},
		},
	}
	ep := engine.ScanEndpoint{ID: "e1", Method: "GET", PathTemplate: "/x/{id}", SecuritySchemeHints: []string{"bearer"}}
	cov := buildScanRunRuleFamilyCoverage(scan, []rules.Rule{rl}, nil, []engine.ScanEndpoint{ep}, false)
	found := false
	for _, c := range cov.IDORPathOrQuery.NotExercisedContributors {
		if c.Code == "declared_secure_openapi_operations_present_auth_headers_absent" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want auth contributor, got %+v", cov.IDORPathOrQuery.NotExercisedContributors)
	}
}

func TestSummarizeFindingsForScan_mem_matchesUnfilteredList(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	id := scan.ID
	for _, in := range []storage.CreateFindingInput{
		{ScanID: id, RuleID: "a", Category: "c", Severity: findings.SeverityHigh, AssessmentTier: "confirmed", Summary: "s1", Evidence: storage.CreateEvidenceInput{}},
		{ScanID: id, RuleID: "b", Category: "c", Severity: findings.SeverityLow, AssessmentTier: "tentative", Summary: "s2", Evidence: storage.CreateEvidenceInput{}},
	} {
		if _, cerr := mem.CreateFinding(ctx, in); cerr != nil {
			t.Fatal(cerr)
		}
	}
	sum, err := mem.SummarizeFindingsForScan(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	list, err := mem.ListByScanID(ctx, id, storage.FindingListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	want := findingsSummaryFromList(list)
	if sum.Total != want.Total || !reflect.DeepEqual(sum.ByAssessmentTier, want.ByAssessmentTier) || !reflect.DeepEqual(sum.BySeverity, want.BySeverity) {
		t.Fatalf("sum %#v want %#v", sum, want)
	}
}

func TestListExecutionRunTallies_mem_matchesFullListProjection(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe", BaseURL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	id := scan.ID
	if rerr := mem.ReplaceScanEndpoints(ctx, id, []engine.EndpointSpec{{Method: "GET", Path: "/x"}}); rerr != nil {
		t.Fatal(rerr)
	}
	eps, err := mem.ListScanEndpoints(ctx, id, storage.EndpointListFilter{})
	if err != nil || len(eps) != 1 {
		t.Fatal(eps, err)
	}
	epID := eps[0].ID
	for _, rec := range []engine.ExecutionRecord{
		{ScanID: id, ScanEndpointID: epID, Phase: engine.PhaseBaseline, RequestMethod: "GET", RequestURL: "http://x", ResponseStatus: 200, RuleID: ""},
		{ScanID: id, ScanEndpointID: epID, Phase: engine.PhaseMutated, RequestMethod: "GET", RequestURL: "http://x", ResponseStatus: 418, RuleID: "r1"},
	} {
		if _, ierr := mem.InsertExecutionRecord(ctx, rec); ierr != nil {
			t.Fatal(ierr)
		}
	}
	full, err := mem.ListExecutions(ctx, id, storage.ExecutionListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	tallies, err := mem.ListExecutionRunTallies(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(tallies) != len(full) {
		t.Fatalf("len tally %d full %d", len(tallies), len(full))
	}
	for i := range tallies {
		if tallies[i].ScanEndpointID != full[i].ScanEndpointID || tallies[i].Phase != full[i].Phase ||
			tallies[i].ResponseStatus != full[i].ResponseStatus || tallies[i].RuleID != full[i].RuleID {
			t.Fatalf("i=%d tally=%+v full=%+v", i, tallies[i], full[i])
		}
	}
}

func TestBuildScanRunGuidance_deterministicOrder(t *testing.T) {
	g := buildScanRunGuidance(engine.Scan{
		RunPhase:                engine.PhaseFailed,
		BaselineRunStatus:       "failed",
		MutationRunStatus:       "failed",
		MutationCandidatesTotal: 0,
	}, 0, 1, false)
	if len(g.NextSteps) < 5 {
		t.Fatalf("want several steps, got %+v", g.NextSteps)
	}
	if g.NextSteps[0].Code != "import_openapi_first" {
		t.Fatalf("first step %+v", g.NextSteps[0])
	}
}
