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

var executionReadRequired = []string{
	"id", "scan_id", "phase", "execution_kind",
	"request", "response", "request_summary", "response_summary",
	"duration_ms", "created_at", "executions_list_path", "execution_detail_path",
	"operator_guide",
}

var executionOperatorGuideKeys = []string{
	"phase_role", "linkage_narration", "summaries_mirror_redacted_snapshots",
	"phase_execution_kind_alignment", "summaries_list_detail_parity",
	"cross_phase_filter_hint", "phase_summary_compare_hint",
}

var findingReadTrustLegendKeys = []string{
	"severity", "rule_declared_confidence", "assessment_tier",
	"evidence_summary", "evidence_inspection", "operator_assessment", "finding_list_row",
}

// executionListItemRequired is GET .../executions items[] (summaries only; no request/response bodies).
var executionListItemRequired = []string{
	"id", "scan_id", "scan_endpoint_id", "phase", "execution_kind",
	"request_summary", "response_summary",
	"duration_ms", "created_at", "execution_detail_path",
}

// findingListItemRequired is GET .../findings items[] (no evidence_summary; no findings_list_path on rows).
var findingListItemRequired = []string{
	"id", "scan_id", "rule_id", "category", "severity",
	"rule_declared_confidence", "assessment_tier", "summary",
	"evidence_uri", "created_at", "finding_detail_path",
}

var executionSnapRequestKeys = []string{"method", "url"}
var executionSnapResponseKeys = []string{"status_code"}
var executionReqSummaryKeys = []string{"method", "url_short", "header_count", "body_byte_length"}
var executionResSummaryKeys = []string{"status_code", "header_count", "body_byte_length"}

var findingReadRequired = []string{
	"id", "scan_id", "rule_id", "category", "severity",
	"rule_declared_confidence", "assessment_tier", "summary",
	"evidence_uri", "created_at", "findings_list_path", "finding_detail_path",
	"read_trust_legend",
}

var evidenceArtifactRequired = []string{
	"id", "finding_id", "baseline_request", "mutated_request",
	"baseline_response_body", "mutated_response_body", "diff_summary", "created_at",
}

var scanRunStatusContractTopLevel = []string{
	"scan", "run", "progress", "summary", "findings_summary",
	"rule_family_coverage", "guidance", "coverage", "protected_route_coverage",
	"diagnostics", "drilldown", "compatibility",
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
	assertJSONKeys(t, top["operator_guide"], executionOperatorGuideKeys)
	assertJSONKeys(t, top["request"], executionSnapRequestKeys)
	assertJSONKeys(t, top["response"], executionSnapResponseKeys)
	assertJSONKeys(t, top["request_summary"], executionReqSummaryKeys)
	assertJSONKeys(t, top["response_summary"], executionResSummaryKeys)

	if string(top["phase"]) != `"baseline"` || string(top["execution_kind"]) != `"baseline"` {
		t.Fatalf("phase/kind %s %s", top["phase"], top["execution_kind"])
	}
	var og map[string]json.RawMessage
	if err := json.Unmarshal(top["operator_guide"], &og); err != nil {
		t.Fatal(err)
	}
	if string(og["phase_role"]) != `"baseline_pre_mutation"` {
		t.Fatalf("operator_guide.phase_role %s", og["phase_role"])
	}
}

func TestContract_executionRead_summariesAlignWithSnapshots(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	eid, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID:              scan.ID,
		ScanEndpointID:      "ep1",
		Phase:               engine.PhaseMutated,
		RuleID:              "rule.z",
		CandidateKey:        "ck1",
		RequestMethod:       "POST",
		RequestURL:          "https://example.com/z?q=1",
		ResponseStatus:      418,
		RequestHeaders:      map[string]string{"A": "1"},
		ResponseHeaders:     map[string]string{"B": "2"},
		RequestBody:         `{"x":1}`,
		ResponseBody:        `ok`,
		ResponseContentType: "text/plain",
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
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var er ExecutionRead
	if err := json.Unmarshal(body, &er); err != nil {
		t.Fatal(err)
	}
	if er.Phase != "mutated" || er.ExecutionKind != er.Phase {
		t.Fatalf("phase/kind %+v", er)
	}
	if er.MutationRuleID != "rule.z" || er.CandidateKey != "ck1" {
		t.Fatalf("rule linkage %+v", er)
	}
	if er.Request.Method != er.RequestSummary.Method || er.RequestSummary.BodyByteLength != len(er.Request.Body) ||
		er.RequestSummary.HeaderCount != len(er.Request.Headers) {
		t.Fatalf("request vs summary %+v", er)
	}
	if er.Response.StatusCode != er.ResponseSummary.StatusCode || er.ResponseSummary.BodyByteLength != len(er.Response.Body) ||
		er.ResponseSummary.HeaderCount != len(er.Response.Headers) {
		t.Fatalf("response vs summary %+v", er)
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
		RuleID:                 "rule.one",
		AssessmentTier:         "tentative",
		RuleSeverity:           "medium",
		RuleDeclaredConfidence: "medium",
		MatcherOutcomes:        []findings.MatcherOutcomeSummary{{Index: 0, Kind: "k", Passed: true}},
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
	assertJSONKeys(t, ftop["read_trust_legend"], findingReadTrustLegendKeys)
	rawOA, ok := ftop["operator_assessment"]
	if !ok {
		t.Fatal("expected operator_assessment on finding read for tentative tier")
	}
	var oa map[string]json.RawMessage
	if uerr := json.Unmarshal(rawOA, &oa); uerr != nil {
		t.Fatal(uerr)
	}
	if _, hasGuide := oa["evidence_sufficiency_guide"]; !hasGuide {
		t.Fatalf("operator_assessment missing evidence_sufficiency_guide: %s", string(rawOA))
	}
	if _, hasInsp := ftop["evidence_inspection"]; !hasInsp {
		t.Fatal("expected evidence_inspection on finding read")
	}
	rawECG, hasECG := ftop["evidence_comparison_guide"]
	if !hasECG {
		t.Fatal("expected evidence_comparison_guide when baseline and mutated execution ids are set")
	}
	var ecg string
	if uerr := json.Unmarshal(rawECG, &ecg); uerr != nil {
		t.Fatal(uerr)
	}
	if ecg == "" || !strings.Contains(ecg, scan.ID) || !strings.Contains(ecg, "b1") || !strings.Contains(ecg, "m1") {
		t.Fatalf("evidence_comparison_guide %q", ecg)
	}
	rawEv, ok := ftop["evidence_summary"]
	if !ok {
		t.Fatal("expected evidence_summary on finding read")
	}
	var ev findings.EvidenceSummaryV1
	if uerr := json.Unmarshal(rawEv, &ev); uerr != nil {
		t.Fatal(uerr)
	}
	if ev.RuleSeverity != "medium" || ev.ImpactSeverity != "medium" {
		t.Fatalf("evidence_summary impact axes: rule_severity=%q impact_severity=%q", ev.RuleSeverity, ev.ImpactSeverity)
	}
	if ev.AssessmentTier != "tentative" || ev.RuleDeclaredConfidence != "medium" {
		t.Fatalf("evidence_summary tier/confidence: %+v", ev)
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

func TestContract_findingRead_invalidUUID(t *testing.T) {
	mem := newMemRepositories()
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/findings/not-a-uuid")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestContract_findingEvidence_invalidUUID(t *testing.T) {
	mem := newMemRepositories()
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/findings/not-a-uuid/evidence")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
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
	var dd map[string]json.RawMessage
	if err := json.Unmarshal(top["drilldown"], &dd); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"scan_id", "scan_detail_path", "endpoints_inventory_path", "executions_list_path",
		"findings_list_path", "run_status_path",
	} {
		if _, ok := dd[k]; !ok {
			t.Fatalf("drilldown missing %q", k)
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
		ScanID: scan.ID, ScanEndpointID: "33333333-3333-3333-3333-333333333333",
		Phase:         engine.PhaseBaseline,
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
	for _, k := range []string{"items", "meta", "scan_navigation"} {
		if _, ok := env[k]; !ok {
			t.Fatalf("missing %q in execution list", k)
		}
	}
	var scanNav ScanListNavigation
	if err := json.Unmarshal(env["scan_navigation"], &scanNav); err != nil {
		t.Fatal(err)
	}
	if scanNav != NewScanListNavigation(scan.ID) {
		t.Fatalf("scan_navigation %+v want %+v", scanNav, NewScanListNavigation(scan.ID))
	}
	var items []json.RawMessage
	if err := json.Unmarshal(env["items"], &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 row, got %d", len(items))
	}
	assertJSONKeys(t, items[0], executionListItemRequired)
	var itemObj map[string]json.RawMessage
	_ = json.Unmarshal(items[0], &itemObj)
	if _, ok := itemObj["request"]; ok {
		t.Fatal("execution list items must not include request body")
	}
	if _, ok := itemObj["response"]; ok {
		t.Fatal("execution list items must not include response body")
	}
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

func TestContract_findingsList_wireKeys(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "r1", Category: "api",
		Severity: findings.SeverityMedium, RuleDeclaredConfidence: "medium", AssessmentTier: "tentative",
		Summary: "s", Evidence: storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings")
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
	for _, k := range []string{"items", "meta", "scan_navigation"} {
		if _, ok := env[k]; !ok {
			t.Fatalf("missing %q in findings list", k)
		}
	}
	var scanNav ScanListNavigation
	if err := json.Unmarshal(env["scan_navigation"], &scanNav); err != nil {
		t.Fatal(err)
	}
	if scanNav != NewScanListNavigation(scan.ID) {
		t.Fatalf("scan_navigation %+v want %+v", scanNav, NewScanListNavigation(scan.ID))
	}
	var items []json.RawMessage
	if err := json.Unmarshal(env["items"], &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 row, got %d", len(items))
	}
	assertJSONKeys(t, items[0], findingListItemRequired)
	var itemObj map[string]json.RawMessage
	_ = json.Unmarshal(items[0], &itemObj)
	if _, ok := itemObj["evidence_summary"]; ok {
		t.Fatal("findings list items must not include evidence_summary")
	}
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
