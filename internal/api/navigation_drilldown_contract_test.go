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
	if jerr := json.Unmarshal(body, &top); jerr != nil {
		t.Fatal(jerr)
	}
	want := scanRunDrilldownHints(scan.ID)
	var got ScanRunDrilldownHints
	if jerr := json.Unmarshal(top["drilldown"], &got); jerr != nil {
		t.Fatal(jerr)
	}
	if got != want {
		t.Fatalf("drilldown got %+v want %+v", got, want)
	}
	base := srv.URL
	respScan, err := http.Get(base + got.ScanDetailPath)
	if err != nil {
		t.Fatal(err)
	}
	bScan, _ := io.ReadAll(respScan.Body)
	_ = respScan.Body.Close()
	if respScan.StatusCode != http.StatusOK {
		t.Fatalf("scan_detail_path %s -> %d %s", got.ScanDetailPath, respScan.StatusCode, bScan)
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
	var execEnv ExecutionListResponse
	if jerr := json.Unmarshal(ebody, &execEnv); jerr != nil {
		t.Fatal(jerr)
	}
	if execEnv.ScanNavigation != NewScanListNavigation(scan.ID) {
		t.Fatalf("filtered executions scan_navigation %+v want %+v", execEnv.ScanNavigation, NewScanListNavigation(scan.ID))
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
	var findEnv FindingListResponse
	if jerr := json.Unmarshal(fbody, &findEnv); jerr != nil {
		t.Fatal(jerr)
	}
	if findEnv.ScanNavigation != NewScanListNavigation(scan.ID) {
		t.Fatalf("filtered findings scan_navigation %+v want %+v", findEnv.ScanNavigation, NewScanListNavigation(scan.ID))
	}
	if len(findEnv.Items) != 1 || findEnv.Items[0].ScanEndpointID != epID {
		t.Fatalf("findings items %+v", findEnv.Items)
	}
	if dd.RunStatusPath == "" {
		t.Fatal("endpoint drilldown missing run_status_path")
	}
	rsResp, err := http.Get(srv.URL + dd.RunStatusPath)
	if err != nil {
		t.Fatal(err)
	}
	rsBody, _ := io.ReadAll(rsResp.Body)
	_ = rsResp.Body.Close()
	if rsResp.StatusCode != http.StatusOK {
		t.Fatalf("run_status_path %s -> %d %s", dd.RunStatusPath, rsResp.StatusCode, rsBody)
	}
}

func TestContract_findingsList_itemIdOpensFindingDetail(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	f, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "r.nav", Category: "c",
		Severity: findings.SeverityLow, RuleDeclaredConfidence: "low", AssessmentTier: "tentative",
		Summary: "nav", Evidence: storage.CreateEvidenceInput{},
	})
	if ferr != nil {
		t.Fatal(ferr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	lresp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	lbody, _ := io.ReadAll(lresp.Body)
	_ = lresp.Body.Close()
	if lresp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", lresp.StatusCode, lbody)
	}
	var list FindingListResponse
	if jerr := json.Unmarshal(lbody, &list); jerr != nil {
		t.Fatal(jerr)
	}
	if len(list.Items) != 1 || list.Items[0].ID != f.ID {
		t.Fatalf("%+v", list.Items)
	}
	dresp, err := http.Get(srv.URL + "/v1/findings/" + f.ID)
	if err != nil {
		t.Fatal(err)
	}
	dbody, _ := io.ReadAll(dresp.Body)
	_ = dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", dresp.StatusCode, dbody)
	}
	var fr FindingRead
	if jerr := json.Unmarshal(dbody, &fr); jerr != nil {
		t.Fatal(jerr)
	}
	if fr.ID != f.ID || fr.RuleID != list.Items[0].RuleID || fr.Summary != list.Items[0].Summary {
		t.Fatalf("detail %+v list %+v", fr, list.Items[0])
	}
}

func TestContract_executionList_itemIdOpensExecutionDetail(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	eid, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: "66666666-6666-6666-6666-666666666666",
		Phase: engine.PhaseBaseline, RequestMethod: "GET", RequestURL: "https://ex/z",
		ResponseStatus: 418,
	})
	if ierr != nil {
		t.Fatal(ierr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	lresp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	lbody, _ := io.ReadAll(lresp.Body)
	_ = lresp.Body.Close()
	if lresp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", lresp.StatusCode, lbody)
	}
	var list ExecutionListResponse
	if jerr := json.Unmarshal(lbody, &list); jerr != nil {
		t.Fatal(jerr)
	}
	if len(list.Items) != 1 || list.Items[0].ID != eid {
		t.Fatalf("%+v", list.Items)
	}
	p := list.Items[0].ExecutionDetailPath
	dresp, err := http.Get(srv.URL + p)
	if err != nil {
		t.Fatal(err)
	}
	dbody, _ := io.ReadAll(dresp.Body)
	_ = dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", dresp.StatusCode, dbody)
	}
	var er ExecutionRead
	if jerr := json.Unmarshal(dbody, &er); jerr != nil {
		t.Fatal(jerr)
	}
	if er.ID != eid || er.Phase != list.Items[0].Phase || er.ExecutionKind != list.Items[0].ExecutionKind {
		t.Fatalf("detail %+v list %+v", er, list.Items[0])
	}
	if er.RequestSummary.Method != list.Items[0].RequestSummary.Method {
		t.Fatalf("method list=%q detail=%q", list.Items[0].RequestSummary.Method, er.RequestSummary.Method)
	}
	if er.ResponseSummary.StatusCode != list.Items[0].ResponseSummary.StatusCode {
		t.Fatalf("status list=%d detail=%d", list.Items[0].ResponseSummary.StatusCode, er.ResponseSummary.StatusCode)
	}
}

func TestContract_executionList_mutatedRowExposesRuleAndCandidateKey(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	ep := "44444444-4444-4444-4444-444444444444"
	_, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: ep, Phase: engine.PhaseMutated,
		RuleID: "rule.alpha", CandidateKey: "ck-nav",
		RequestMethod: "GET", RequestURL: "https://ex/x", ResponseStatus: 200,
	})
	if ierr != nil {
		t.Fatal(ierr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal(body)
	}
	var env ExecutionListResponse
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Items) != 1 {
		t.Fatalf("%+v", env.Items)
	}
	it := env.Items[0]
	if it.MutationRuleID != "rule.alpha" || it.CandidateKey != "ck-nav" || it.ScanEndpointID != ep {
		t.Fatalf("%+v", it)
	}
}
