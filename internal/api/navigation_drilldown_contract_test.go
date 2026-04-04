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

func TestContract_scanRunStatus_drilldownPaths(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/a"}}); rerr != nil {
		t.Fatal(rerr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	want := scanRunDrilldownHints(scan.ID)
	var got ScanRunDrilldownHints
	if err := json.Unmarshal(top["drilldown"], &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("drilldown got %+v want %+v", got, want)
	}
}

func TestContract_endpointDetail_filteredListsFromDrilldown(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/a"}}); rerr != nil {
		t.Fatal(rerr)
	}
	eps, err := mem.ListScanEndpoints(ctx, scan.ID, storage.EndpointListFilter{})
	if err != nil || len(eps) != 1 {
		t.Fatal(eps, err)
	}
	epID := eps[0].ID
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: epID, Phase: engine.PhaseBaseline,
		RequestMethod: "GET", RequestURL: "http://x/", ResponseStatus: 200,
	}); ierr != nil {
		t.Fatal(ierr)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "r1", Category: "c",
		Severity: findings.SeverityLow, RuleDeclaredConfidence: "low", AssessmentTier: "tentative",
		Summary: "s", ScanEndpointID: epID, Evidence: storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	dresp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints/" + epID)
	if err != nil {
		t.Fatal(err)
	}
	dbody, err := io.ReadAll(dresp.Body)
	_ = dresp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("detail status %d %s", dresp.StatusCode, dbody)
	}
	var top map[string]json.RawMessage
	if jerr := json.Unmarshal(dbody, &top); jerr != nil {
		t.Fatal(jerr)
	}
	var dd EndpointDrilldownHints
	if jerr := json.Unmarshal(top["drilldown"], &dd); jerr != nil {
		t.Fatal(jerr)
	}
	execURL := srv.URL + dd.ExecutionsListPath + "?" + dd.ExecutionsListQuery
	execResp, err := http.Get(execURL)
	if err != nil {
		t.Fatal(err)
	}
	ebody, _ := io.ReadAll(execResp.Body)
	_ = execResp.Body.Close()
	if execResp.StatusCode != http.StatusOK {
		t.Fatalf("executions filtered %d %s", execResp.StatusCode, ebody)
	}
	var execEnv struct {
		Items []struct {
			ScanEndpointID string `json:"scan_endpoint_id"`
		} `json:"items"`
	}
	if jerr := json.Unmarshal(ebody, &execEnv); jerr != nil {
		t.Fatal(jerr)
	}
	if len(execEnv.Items) != 1 || execEnv.Items[0].ScanEndpointID != epID {
		t.Fatalf("executions items %+v", execEnv.Items)
	}
	findURL := srv.URL + dd.FindingsListPath + "?" + dd.FindingsListQuery
	findResp, err := http.Get(findURL)
	if err != nil {
		t.Fatal(err)
	}
	fbody, _ := io.ReadAll(findResp.Body)
	_ = findResp.Body.Close()
	if findResp.StatusCode != http.StatusOK {
		t.Fatalf("findings filtered %d %s", findResp.StatusCode, fbody)
	}
	var findEnv struct {
		Items []struct {
			ScanEndpointID string `json:"scan_endpoint_id"`
		} `json:"items"`
	}
	if jerr := json.Unmarshal(fbody, &findEnv); jerr != nil {
		t.Fatal(jerr)
	}
	if len(findEnv.Items) != 1 || findEnv.Items[0].ScanEndpointID != epID {
		t.Fatalf("findings items %+v", findEnv.Items)
	}
}
