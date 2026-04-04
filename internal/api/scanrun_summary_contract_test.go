package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

func TestContract_scanRunStatus_summaryAndFindingsSummaryKeys(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "r1", Category: "c",
		Severity: findings.SeverityHigh, RuleDeclaredConfidence: "high", AssessmentTier: "confirmed",
		Summary: "s", Evidence: storage.CreateEvidenceInput{},
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
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	var summ map[string]json.RawMessage
	if err := json.Unmarshal(top["summary"], &summ); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"endpoints_imported", "baseline", "mutation", "findings_created"} {
		if _, ok := summ[k]; !ok {
			t.Fatalf("summary missing %q", k)
		}
	}
	var fs map[string]json.RawMessage
	if err := json.Unmarshal(top["findings_summary"], &fs); err != nil {
		t.Fatal(err)
	}
	if _, ok := fs["total"]; !ok {
		t.Fatal("findings_summary.total")
	}
	if raw, ok := fs["by_assessment_tier"]; ok {
		var m map[string]int
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if m["confirmed"] < 1 {
			t.Fatalf("by_assessment_tier %+v", m)
		}
	} else {
		t.Fatal("expected by_assessment_tier")
	}
	if raw, ok := fs["by_severity"]; ok {
		var m map[string]int
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if m["high"] < 1 {
			t.Fatalf("by_severity %+v", m)
		}
	} else {
		t.Fatal("expected by_severity")
	}
}

func TestContract_endpointInventory_listAndDetailSummaryMatch(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/x"}}); rerr != nil {
		t.Fatal(rerr)
	}
	eps, err := mem.ListScanEndpoints(ctx, scan.ID, storage.EndpointListFilter{})
	if err != nil || len(eps) != 1 {
		t.Fatal(eps, err)
	}
	epID := eps[0].ID
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: epID, Phase: engine.PhaseBaseline,
		RequestMethod: "GET", RequestURL: "http://h/", ResponseStatus: 201,
	}); ierr != nil {
		t.Fatal(ierr)
	}
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: epID, Phase: engine.PhaseMutated, RuleID: "r",
		RequestMethod: "GET", RequestURL: "http://h/m", ResponseStatus: 403,
	}); ierr != nil {
		t.Fatal(ierr)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "r", Category: "c", Severity: findings.SeverityLow,
		AssessmentTier: "tentative", Summary: "s", ScanEndpointID: epID,
		Evidence: storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	lresp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints?include_summary=true&limit=10")
	if err != nil {
		t.Fatal(err)
	}
	lbody, _ := io.ReadAll(lresp.Body)
	_ = lresp.Body.Close()
	if lresp.StatusCode != http.StatusOK {
		t.Fatalf("list %d %s", lresp.StatusCode, lbody)
	}
	var listEnv struct {
		Items []struct {
			ID      string `json:"id"`
			Summary struct {
				BaselineExecutionsRecorded int `json:"baseline_executions_recorded"`
				MutationExecutionsRecorded int `json:"mutation_executions_recorded"`
				FindingsRecorded           int `json:"findings_recorded"`
			} `json:"summary"`
		} `json:"items"`
	}
	if jerr := json.Unmarshal(lbody, &listEnv); jerr != nil {
		t.Fatal(jerr)
	}
	if len(listEnv.Items) != 1 {
		t.Fatalf("%+v", listEnv.Items)
	}
	li := listEnv.Items[0]
	dresp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints/" + epID)
	if err != nil {
		t.Fatal(err)
	}
	dbody, _ := io.ReadAll(dresp.Body)
	_ = dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("detail %d %s", dresp.StatusCode, dbody)
	}
	var detail struct {
		Summary struct {
			BaselineExecutionsRecorded int `json:"baseline_executions_recorded"`
			MutationExecutionsRecorded int `json:"mutation_executions_recorded"`
			FindingsRecorded           int `json:"findings_recorded"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(dbody, &detail); err != nil {
		t.Fatal(err)
	}
	if li.Summary != detail.Summary {
		t.Fatalf("list %+v detail %+v", li.Summary, detail.Summary)
	}
}

func TestContract_endpointInventory_includeSummaryFalseOmitsSummaryObject(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/z"}}); rerr != nil {
		t.Fatal(rerr)
	}
	eps, err := mem.ListScanEndpoints(ctx, scan.ID, storage.EndpointListFilter{})
	if err != nil || len(eps) != 1 {
		t.Fatal(eps, err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints?include_summary=false&limit=10")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(top["items"], &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatal(items)
	}
	if _, ok := items[0]["summary"]; ok {
		t.Fatalf("expected no summary key, got %s", items[0]["summary"])
	}
}
