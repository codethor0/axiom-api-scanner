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

var endpointDetailCanonicalKeys = []string{
	"id", "scan_id", "method", "path_template", "request_body_json",
	"declares_openapi_security", "created_at", "summary", "investigation", "drilldown",
}

func TestGetScanEndpoint_detailWireShape(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{
		{Method: "GET", Path: "/items/{id}", SecuritySchemeHints: []string{"bearer"}},
	}); rerr != nil {
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
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: epID, Phase: engine.PhaseMutated, RuleID: "r1",
		RequestMethod: "GET", RequestURL: "http://x/", ResponseStatus: 201,
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
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints/" + epID)
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
	for _, k := range endpointDetailCanonicalKeys {
		if _, ok := top[k]; !ok {
			t.Fatalf("missing %q in %s", k, body)
		}
	}
	var sum map[string]json.RawMessage
	if err := json.Unmarshal(top["summary"], &sum); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"baseline_executions_recorded", "mutation_executions_recorded", "findings_recorded"} {
		if _, ok := sum[k]; !ok {
			t.Fatalf("summary missing %q", k)
		}
	}
	var inv map[string]json.RawMessage
	if err := json.Unmarshal(top["investigation"], &inv); err != nil {
		t.Fatal(err)
	}
	var bl map[string]int
	if err := json.Unmarshal(inv["baseline"], &bl); err != nil {
		t.Fatal(err)
	}
	if bl["latest_response_status"] != 200 {
		t.Fatalf("baseline investigation %+v", bl)
	}
	var mu map[string]int
	if err := json.Unmarshal(inv["mutation"], &mu); err != nil {
		t.Fatal(err)
	}
	if mu["latest_response_status"] != 201 {
		t.Fatalf("mutation investigation %+v", mu)
	}
	var fd map[string]map[string]int
	if err := json.Unmarshal(inv["findings"], &fd); err != nil {
		t.Fatal(err)
	}
	if fd["by_assessment_tier"]["tentative"] != 1 {
		t.Fatalf("findings investigation %+v", fd)
	}
	var dd map[string]json.RawMessage
	if err := json.Unmarshal(top["drilldown"], &dd); err != nil {
		t.Fatal(err)
	}
	wantScanEp, _ := json.Marshal(epID)
	wantQ, _ := json.Marshal("scan_endpoint_id=" + epID)
	if string(dd["scan_endpoint_id"]) != string(wantScanEp) {
		t.Fatalf("drilldown %+v", dd)
	}
	if string(dd["executions_list_query"]) != string(wantQ) || string(dd["findings_list_query"]) != string(wantQ) {
		t.Fatalf("drilldown queries %+v want %s", dd, string(wantQ))
	}
	if string(top["declares_openapi_security"]) != "true" {
		t.Fatalf("want declares_openapi_security true: %s", body)
	}
}

func TestGetScanEndpoint_detailNoExecutionsOrFindings(t *testing.T) {
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
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints/" + epID)
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
	for _, k := range endpointDetailCanonicalKeys {
		if _, ok := top[k]; !ok {
			t.Fatalf("missing %q", k)
		}
	}
	var inv map[string]json.RawMessage
	if err := json.Unmarshal(top["investigation"], &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv) != 0 {
		t.Fatalf("want empty investigation object, got %s", top["investigation"])
	}
	var dd map[string]json.RawMessage
	if err := json.Unmarshal(top["drilldown"], &dd); err != nil {
		t.Fatal(err)
	}
	wantQ, _ := json.Marshal("scan_endpoint_id=" + epID)
	if string(dd["executions_list_query"]) != string(wantQ) || string(dd["findings_list_query"]) != string(wantQ) {
		t.Fatalf("drilldown %+v", dd)
	}
	var sum map[string]int
	if err := json.Unmarshal(top["summary"], &sum); err != nil {
		t.Fatal(err)
	}
	if sum["baseline_executions_recorded"] != 0 || sum["mutation_executions_recorded"] != 0 || sum["findings_recorded"] != 0 {
		t.Fatalf("summary %+v", sum)
	}
}

func TestGetScanEndpoint_detailLinkedFindingsUnknownTierKeepsCountOmitsBucket(t *testing.T) {
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
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "r1", Category: "c",
		Severity: findings.SeverityLow, RuleDeclaredConfidence: "low", AssessmentTier: "other",
		Summary: "s", ScanEndpointID: epID, Evidence: storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints/" + epID)
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
	var inv map[string]json.RawMessage
	if err := json.Unmarshal(top["investigation"], &inv); err != nil {
		t.Fatal(err)
	}
	var findingsObj map[string]json.RawMessage
	if err := json.Unmarshal(inv["findings"], &findingsObj); err != nil {
		t.Fatal(err)
	}
	if _, hasTier := findingsObj["by_assessment_tier"]; hasTier {
		t.Fatalf("expected no tier buckets for unknown tier, got %s", inv["findings"])
	}
}

func TestGetScanEndpoint_notFound(t *testing.T) {
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
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints/00000000-0000-0000-0000-000000000099")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
