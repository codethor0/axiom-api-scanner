package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

var findingsListItemCanonicalKeys = []string{
	"id", "rule_id", "severity", "rule_declared_confidence", "assessment_tier",
	"scan_id", "category", "evidence_uri", "summary", "created_at",
}

var executionsListItemCanonicalKeys = []string{
	"id", "scan_id", "phase", "execution_kind",
	"request_summary", "response_summary", "duration_ms", "created_at",
}

func TestFindingsList_wireShape_andFiltered(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	epID := "00000000-0000-0000-0000-0000000000aa"
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "rule.high", Category: "api",
		Severity: findings.SeverityHigh, RuleDeclaredConfidence: "high", AssessmentTier: "confirmed",
		Summary: "x", ScanEndpointID: epID, Evidence: storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "rule.low", Category: "api",
		Severity: findings.SeverityLow, RuleDeclaredConfidence: "low", AssessmentTier: "tentative",
		Summary: "y", Evidence: storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	t.Run("unfiltered", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?limit=10")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d %s", resp.StatusCode, body)
		}
		assertFindingsListWire(t, body, 2)
	})

	t.Run("filtered severity", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?severity=high")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d %s", resp.StatusCode, body)
		}
		var env FindingListResponse
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatal(err)
		}
		if len(env.Items) != 1 || env.Items[0].Severity != findings.SeverityHigh {
			t.Fatalf("%+v", env.Items)
		}
	})
}

func TestFindingsList_rejectsInvalidAssessmentTierFilter(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?assessment_tier=maybe")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
}

func TestFindingsList_scanEndpointIDFilter(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{
		{Method: "GET", Path: "/a"},
		{Method: "GET", Path: "/b"},
	}); rerr != nil {
		t.Fatal(rerr)
	}
	eps, err := mem.ListScanEndpoints(ctx, scan.ID, storage.EndpointListFilter{})
	if err != nil || len(eps) != 2 {
		t.Fatal(eps, err)
	}
	epA, epB := eps[0].ID, eps[1].ID
	for _, in := range []struct {
		epID   string
		ruleID string
	}{
		{epID: epA, ruleID: "r.a"},
		{epID: epB, ruleID: "r.b"},
	} {
		if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
			ScanID: scan.ID, RuleID: in.ruleID, Category: "c",
			Severity: findings.SeverityLow, RuleDeclaredConfidence: "low", AssessmentTier: "tentative",
			Summary: "s", ScanEndpointID: in.epID, Evidence: storage.CreateEvidenceInput{},
		}); ferr != nil {
			t.Fatal(ferr)
		}
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?scan_endpoint_id=" + epA)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	var env FindingListResponse
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Items) != 1 || env.Items[0].RuleID != "r.a" {
		t.Fatalf("%+v", env.Items)
	}
}

func TestFindingsList_rejectsInvalidScanEndpointID(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?scan_endpoint_id=bad")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestFindingsList_rejectsInvalidSeverityFilter(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?severity=unlikely")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "invalid_filter") {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
}

func TestExecutionsList_wireShape_andFiltered(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	ep := "11111111-1111-1111-1111-111111111111"
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: ep, Phase: engine.PhaseBaseline,
		RequestMethod: "GET", RequestURL: "https://ex/a", RequestBody: "req-body",
		ResponseStatus: 200, ResponseBody: "resp-body",
	}); ierr != nil {
		t.Fatal(ierr)
	}
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: ep, Phase: engine.PhaseMutated, RuleID: "r1",
		RequestMethod: "GET", RequestURL: "https://ex/b",
		ResponseStatus: 401,
	}); ierr != nil {
		t.Fatal(ierr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	t.Run("unfiltered", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions?limit=10")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d %s", resp.StatusCode, body)
		}
		assertExecutionsListWire(t, body, 2)
		var top map[string]json.RawMessage
		_ = json.Unmarshal(body, &top)
		var items []map[string]json.RawMessage
		_ = json.Unmarshal(top["items"], &items)
		for _, it := range items {
			if _, ok := it["request"]; ok {
				t.Fatalf("list item must not include request object: %v", it)
			}
			if _, ok := it["response"]; ok {
				t.Fatalf("list item must not include response object: %v", it)
			}
		}
	})

	t.Run("filtered phase and response_status", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions?phase=mutated&response_status=401")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d %s", resp.StatusCode, body)
		}
		var env ExecutionListResponse
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatal(err)
		}
		if len(env.Items) != 1 || env.Items[0].Phase != "mutated" || env.Items[0].ResponseSummary.StatusCode != 401 {
			t.Fatalf("%+v", env.Items)
		}
	})
}

func TestExecutionsList_rejectsInvalidResponseStatus(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions?response_status=abc")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
}

func TestExecutionsList_rejectsInvalidScanEndpointID(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions?scan_endpoint_id=not-a-uuid")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
}

func TestExecutionsList_rejectsInvalidPhase(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions?phase=planned")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
}

func assertFindingsListWire(t *testing.T, body []byte, wantItems int) {
	t.Helper()
	var env FindingListResponse
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Items) != wantItems {
		t.Fatalf("items %d want %d", len(env.Items), wantItems)
	}
	if env.Meta.Limit == 0 || env.Meta.Sort == "" || env.Meta.Order == "" {
		t.Fatalf("meta %+v", env.Meta)
	}
	raw := env.Items[0]
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range findingsListItemCanonicalKeys {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %q in %s", k, b)
		}
	}
	if _, ok := m["evidence_summary"]; ok {
		t.Fatal("evidence_summary must not appear in list items")
	}
}

func assertExecutionsListWire(t *testing.T, body []byte, wantItems int) {
	t.Helper()
	var env ExecutionListResponse
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Items) != wantItems {
		t.Fatalf("items %d want %d", len(env.Items), wantItems)
	}
	b, err := json.Marshal(env.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range executionsListItemCanonicalKeys {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %q in %s", k, b)
		}
	}
	rs := m["request_summary"]
	var reqSum map[string]json.RawMessage
	_ = json.Unmarshal(rs, &reqSum)
	for _, k := range []string{"method", "url_short", "header_count", "body_byte_length"} {
		if _, ok := reqSum[k]; !ok {
			t.Fatalf("request_summary missing %q", k)
		}
	}
}
