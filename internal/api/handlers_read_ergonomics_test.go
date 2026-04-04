package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

func TestListExecutions_executionKindAliasAndConflict(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, Phase: engine.PhaseBaseline, RequestMethod: "GET",
		RequestURL: "https://example.com/a", ResponseStatus: 200,
	}); ierr != nil {
		t.Fatal(ierr)
	}
	mid, err := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, Phase: engine.PhaseMutated, RuleID: "r1", CandidateKey: "ck",
		RequestMethod: "GET", RequestURL: "https://example.com/b", ResponseStatus: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	base := srv.URL + "/v1/scans/" + scan.ID + "/executions"

	resp, err := http.Get(base + "?execution_kind=mutated")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	var env ExecutionListResponse
	if uerr := json.Unmarshal(body, &env); uerr != nil {
		t.Fatal(uerr)
	}
	if len(env.Items) != 1 || env.Items[0].ID != mid || env.Items[0].CandidateKey != "ck" {
		t.Fatalf("mutated filter %+v", env.Items)
	}

	resp2, err := http.Get(base + "?phase=baseline&execution_kind=mutated")
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", resp2.StatusCode, b2)
	}

	resp3, err := http.Get(base + "?rule_id=r1&mutation_rule_id=other")
	if err != nil {
		t.Fatal(err)
	}
	b3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 conflicting rule filters, got %d: %s", resp3.StatusCode, b3)
	}
}

func TestListExecutions_mutationRuleIDFilter(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, Phase: engine.PhaseMutated, RuleID: "rule.target", CandidateKey: "k1",
		RequestMethod: "GET", RequestURL: "https://example.com/z", ResponseStatus: 200,
	}); ierr != nil {
		t.Fatal(ierr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions?mutation_rule_id=rule.target")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	var env ExecutionListResponse
	if uerr := json.Unmarshal(body, &env); uerr != nil {
		t.Fatal(uerr)
	}
	if len(env.Items) != 1 || env.Items[0].MutationRuleID != "rule.target" {
		t.Fatalf("%+v", env.Items)
	}
}

func TestListFindings_ruleIDFilter(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	for _, rid := range []string{"rule.alpha", "rule.beta"} {
		if _, cerr := mem.CreateFinding(ctx, storage.CreateFindingInput{
			ScanID: scan.ID, RuleID: rid, Category: "c",
			Severity: findings.SeverityLow, RuleDeclaredConfidence: "low", AssessmentTier: "tentative",
			Summary: "s", Evidence: storage.CreateEvidenceInput{},
		}); cerr != nil {
			t.Fatal(cerr)
		}
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?rule_id=rule.alpha")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	var env FindingListResponse
	if uerr := json.Unmarshal(body, &env); uerr != nil {
		t.Fatal(uerr)
	}
	if len(env.Items) != 1 || env.Items[0].RuleID != "rule.alpha" {
		t.Fatalf("%+v", env.Items)
	}
}
