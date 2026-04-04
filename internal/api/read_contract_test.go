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

var executionReadRequired = []string{
	"id", "scan_id", "phase", "execution_kind",
	"request", "response", "request_summary", "response_summary",
	"duration_ms", "created_at",
}

var executionSnapRequestKeys = []string{"method", "url"}
var executionSnapResponseKeys = []string{"status_code"}
var executionReqSummaryKeys = []string{"method", "url_short", "header_count", "body_byte_length"}
var executionResSummaryKeys = []string{"status_code", "header_count", "body_byte_length"}

var findingReadRequired = []string{
	"id", "scan_id", "rule_id", "category", "severity",
	"rule_declared_confidence", "assessment_tier", "summary",
	"evidence_uri", "created_at",
}

var evidenceArtifactRequired = []string{
	"id", "finding_id", "baseline_request", "mutated_request",
	"baseline_response_body", "mutated_response_body", "diff_summary", "created_at",
}

var scanRunStatusContractTopLevel = []string{
	"scan", "run", "progress", "summary", "findings_summary",
	"rule_family_coverage", "guidance", "coverage", "protected_route_coverage",
	"diagnostics", "compatibility",
}

func assertJSONKeys(t *testing.T, raw json.RawMessage, required []string) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %q in %s", k, string(raw))
		}
	}
}

func TestContract_executionRead_wireKeys(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	eid, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID:              scan.ID,
		ScanEndpointID:      "ep1",
		Phase:               engine.PhaseBaseline,
		RequestMethod:       "GET",
		RequestURL:          "https://example.com/r",
		ResponseStatus:      204,
		RequestHeaders:      map[string]string{"A": "1"},
		ResponseHeaders:     map[string]string{"C": "2"},
		RequestBody:         "x",
		ResponseBody:        "y",
		ResponseContentType: "application/json",
	})
	if ierr != nil {
		t.Fatal(ierr)
	}

	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions/" + eid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	assertJSONKeys(t, body, executionReadRequired)

	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, top["request"], executionSnapRequestKeys)
	assertJSONKeys(t, top["response"], executionSnapResponseKeys)
	assertJSONKeys(t, top["request_summary"], executionReqSummaryKeys)
	assertJSONKeys(t, top["response_summary"], executionResSummaryKeys)

	if string(top["phase"]) != `"baseline"` || string(top["execution_kind"]) != `"baseline"` {
		t.Fatalf("phase/kind %s %s", top["phase"], top["execution_kind"])
	}
}

func TestContract_findingReadAndEvidence_wireKeys(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	evSum, serr := findings.MarshalEvidenceSummaryJSON(findings.EvidenceSummaryV1{
		MatcherOutcomes: []findings.MatcherOutcomeSummary{{Index: 0, Kind: "k", Passed: true}},
	})
	if serr != nil {
		t.Fatal(serr)
	}
	f, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID:                 scan.ID,
		RuleID:                 "rule.one",
		Category:               "cat",
		Severity:               findings.SeverityMedium,
		RuleDeclaredConfidence: "medium",
		AssessmentTier:         "tentative",
		Summary:                "s",
		EvidenceSummary:        evSum,
		ScanEndpointID:         "e1",
		BaselineExecutionID:    "b1",
		MutatedExecutionID:     "m1",
		Evidence:               storage.CreateEvidenceInput{DiffSummary: "d"},
	})
	if ferr != nil {
		t.Fatal(ferr)
	}

	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/findings/" + f.ID)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("finding status %d: %s", resp.StatusCode, fb)
	}
	assertJSONKeys(t, fb, findingReadRequired)
	var ftop map[string]json.RawMessage
	if uerr := json.Unmarshal(fb, &ftop); uerr != nil {
		t.Fatal(uerr)
	}
	if _, ok := ftop["evidence_inspection"]; !ok {
		t.Fatal("expected evidence_inspection on finding read")
	}

	respe, err := http.Get(srv.URL + "/v1/findings/" + f.ID + "/evidence")
	if err != nil {
		t.Fatal(err)
	}
	eb, err := io.ReadAll(respe.Body)
	_ = respe.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if respe.StatusCode != http.StatusOK {
		t.Fatalf("evidence status %d: %s", respe.StatusCode, eb)
	}
	assertJSONKeys(t, eb, evidenceArtifactRequired)
}

func TestContract_scanRunStatus_wireKeys_withCoverageAndDiagnostics(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/x"}}); rerr != nil {
		t.Fatal(rerr)
	}
	h := testHandler(mem)
	h.RulesDir = filepath.Join("..", "..", "rules", "builtin")
	srv := httptest.NewServer(h.Routes())
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
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range scanRunStatusContractTopLevel {
		if _, ok := top[k]; !ok {
			t.Fatalf("missing %q", k)
		}
	}
	var cov map[string]json.RawMessage
	if err := json.Unmarshal(top["coverage"], &cov); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"auth_headers_configured", "endpoints_declaring_security"} {
		if _, ok := cov[k]; !ok {
			t.Fatalf("coverage.%s", k)
		}
	}
	var pr map[string]json.RawMessage
	if err := json.Unmarshal(top["protected_route_coverage"], &pr); err != nil {
		t.Fatal(err)
	}
	if _, ok := pr["executions_repository_configured"]; !ok {
		t.Fatalf("protected_route_coverage keys: %v", pr)
	}
	var diag map[string]json.RawMessage
	if err := json.Unmarshal(top["diagnostics"], &diag); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"blocked_detail", "skipped_detail", "consistency_detail"} {
		if _, ok := diag[k]; !ok {
			t.Fatalf("diagnostics.%s", k)
		}
	}
}

func TestContract_executionList_wireKeys(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, Phase: engine.PhaseBaseline,
		RequestMethod: "GET", RequestURL: "https://example.com/", ResponseStatus: 200,
	}); ierr != nil {
		t.Fatal(ierr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]json.RawMessage
	if jerr := json.Unmarshal(body, &env); jerr != nil {
		t.Fatal(jerr)
	}
	for _, k := range []string{"items", "meta"} {
		if _, ok := env[k]; !ok {
			t.Fatalf("missing %q in execution list", k)
		}
	}
	var items []json.RawMessage
	if err := json.Unmarshal(env["items"], &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 row, got %d", len(items))
	}
	assertJSONKeys(t, items[0], executionReadRequired)
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(env["meta"], &meta); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"limit", "sort", "order", "has_more"} {
		if _, ok := meta[k]; !ok {
			t.Fatalf("meta missing %s", k)
		}
	}
}
