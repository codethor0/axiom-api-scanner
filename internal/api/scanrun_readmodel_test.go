package api

import (
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
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
	mut := []engine.ExecutionRecord{
		{Phase: engine.PhaseMutated, RuleID: "r1"},
	}
	cov := buildScanRunRuleFamilyCoverage(scan, []rules.Rule{rl}, mut)
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
	cov := buildScanRunRuleFamilyCoverage(scan, []rules.Rule{rl}, nil)
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
