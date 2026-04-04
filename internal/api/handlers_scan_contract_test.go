package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

var scanRunStatusRequiredTopLevel = []string{
	"scan", "run", "progress", "summary", "findings_summary",
	"rule_family_coverage", "guidance", "coverage", "diagnostics", "compatibility",
}

var scanRunStatusNestedKeys = map[string][]string{
	"guidance": {"next_steps"},
	"diagnostics": {
		"blocked_detail", "skipped_detail", "consistency_detail",
	},
}

func assertScanRunStatusWireShape(t *testing.T, body []byte) {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range scanRunStatusRequiredTopLevel {
		if _, ok := top[k]; !ok {
			t.Fatalf("missing top-level key %q in %s", k, string(body))
		}
	}
	for parent, keys := range scanRunStatusNestedKeys {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(top[parent], &nested); err != nil {
			t.Fatalf("unmarshal %s: %v", parent, err)
		}
		for _, k := range keys {
			if _, ok := nested[k]; !ok {
				t.Fatalf("missing %s.%q", parent, k)
			}
		}
	}
}

func TestScanRunStatus_wireShape_successfulRun(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/r/{id}"}}); rerr != nil {
		t.Fatal(rerr)
	}
	if uerr := mem.UpdateBaselineState(ctx, scan.ID, storage.BaselineState{Status: "succeeded", Total: 1, Done: 1}); uerr != nil {
		t.Fatal(uerr)
	}
	if uerr := mem.UpdateMutationState(ctx, scan.ID, storage.MutationState{Status: "succeeded", Total: 1, Done: 1}); uerr != nil {
		t.Fatal(uerr)
	}
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: "ep1", Phase: engine.PhaseMutated,
		RuleID: "axiom.idor.path_swap.v1", RequestMethod: "GET", RequestURL: "http://example/r/1",
	}); ierr != nil {
		t.Fatal(ierr)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "axiom.idor.path_swap.v1", Category: "c",
		Severity: findings.SeverityHigh, RuleDeclaredConfidence: "high", AssessmentTier: "confirmed",
		Summary: "p", ScanEndpointID: "e1", BaselineExecutionID: "b1", MutatedExecutionID: "m1",
		Evidence: storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	h := testHandler(mem)
	h.RulesDir = filepath.Join("..", "..", "rules", "builtin")
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	assertScanRunStatusWireShape(t, body)
	var st ScanRunStatusResponse
	if errRN := json.Unmarshal(body, &st); errRN != nil {
		t.Fatal(errRN)
	}
	if len(st.Diagnostics.ConsistencyDetail) != 0 {
		t.Fatalf("expected no consistency drift, got %+v", st.Diagnostics.ConsistencyDetail)
	}
}

func TestScanRunStatus_wireShape_blockedRun(t *testing.T) {
	mem := newMemRepositories()
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	cr, err := http.Post(srv.URL+"/v1/scans", "application/json", strings.NewReader(`{"target_label":"t","safety_mode":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	var scan engine.Scan
	_ = json.NewDecoder(cr.Body).Decode(&scan)
	_ = cr.Body.Close()
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	assertScanRunStatusWireShape(t, body)
	var st ScanRunStatusResponse
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.RuleFamilyCoverage.UnavailableReason == nil || st.RuleFamilyCoverage.UnavailableReason.Code != "rules_dir_not_configured" {
		t.Fatalf("coverage unavailable: %+v", st.RuleFamilyCoverage.UnavailableReason)
	}
}

func TestScanRunStatus_wireShape_failedRun(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if perr := mem.PatchScanRunPhase(ctx, scan.ID, engine.PhaseFailed, "stop"); perr != nil {
		t.Fatal(perr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	assertScanRunStatusWireShape(t, body)
	var st ScanRunStatusResponse
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.Run.Phase != string(engine.PhaseFailed) || !st.Diagnostics.ResumeRecommended {
		t.Fatalf("%+v", st)
	}
}

func TestScanRunStatus_findingsCountDriftDiagnostic(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/x"}}); rerr != nil {
		t.Fatal(rerr)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "r1", Category: "c",
		Severity: findings.SeverityLow, RuleDeclaredConfidence: "low", AssessmentTier: "tentative",
		Summary: "s", ScanEndpointID: "e1", BaselineExecutionID: "b1", MutatedExecutionID: "m1",
		Evidence: storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	mem.mu.Lock()
	s := mem.scans[scan.ID]
	s.FindingsCount = 99
	mem.scans[scan.ID] = s
	mem.mu.Unlock()

	h := testHandler(mem)
	h.RulesDir = filepath.Join("..", "..", "rules", "builtin")
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st ScanRunStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range st.Diagnostics.ConsistencyDetail {
		if l.Code == "findings_count_drift" {
			found = true
			if !strings.Contains(l.Detail, "99") || !strings.Contains(l.Detail, "1") {
				t.Fatalf("detail should cite counts: %q", l.Detail)
			}
			break
		}
	}
	if !found {
		t.Fatalf("want findings_count_drift, got %+v", st.Diagnostics.ConsistencyDetail)
	}
}
