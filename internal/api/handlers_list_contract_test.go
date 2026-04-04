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
	"id", "scan_id", "rule_id", "category", "severity",
	"rule_declared_confidence", "assessment_tier", "summary", "evidence_uri", "created_at",
	"finding_detail_path",
}

var executionsListItemCanonicalKeys = []string{
	"id", "scan_id", "scan_endpoint_id", "phase", "execution_kind",
	"request_summary", "response_summary", "duration_ms", "created_at",
	"execution_detail_path",
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

func TestFindingsList_combinedFiltersAND(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	ep1 := "11111111-1111-1111-1111-111111111101"
	ep2 := "11111111-1111-1111-1111-111111111102"
	ep3 := "11111111-1111-1111-1111-111111111103"
	for _, in := range []storage.CreateFindingInput{
		{ScanID: scan.ID, RuleID: "rule.keep", Category: "c",
			Severity: findings.SeverityHigh, RuleDeclaredConfidence: "high", AssessmentTier: "confirmed",
			Summary: "a", ScanEndpointID: ep1, BaselineExecutionID: "b1", MutatedExecutionID: "m1",
			Evidence: storage.CreateEvidenceInput{}},
		{ScanID: scan.ID, RuleID: "rule.other", Category: "c",
			Severity: findings.SeverityHigh, RuleDeclaredConfidence: "high", AssessmentTier: "tentative",
			Summary: "b", ScanEndpointID: ep2, BaselineExecutionID: "b2", MutatedExecutionID: "m2",
			Evidence: storage.CreateEvidenceInput{}},
		{ScanID: scan.ID, RuleID: "rule.keep", Category: "c",
			Severity: findings.SeverityLow, RuleDeclaredConfidence: "low", AssessmentTier: "confirmed",
			Summary: "c", ScanEndpointID: ep3, BaselineExecutionID: "b3", MutatedExecutionID: "m3",
			Evidence: storage.CreateEvidenceInput{}},
	} {
		if _, ferr := mem.CreateFinding(ctx, in); ferr != nil {
			t.Fatal(ferr)
		}
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	q := "/v1/scans/" + scan.ID + "/findings?rule_id=rule.keep&assessment_tier=confirmed&severity=high"
	resp, err := http.Get(srv.URL + q)
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
	if len(env.Items) != 1 || env.Items[0].RuleID != "rule.keep" || env.Items[0].AssessmentTier != "confirmed" ||
		env.Items[0].Severity != findings.SeverityHigh {
		t.Fatalf("%+v", env.Items)
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
	if ein, ok := m["evidence_inspection"]; ok {
		var insp map[string]json.RawMessage
		if err := json.Unmarshal(ein, &insp); err != nil {
			t.Fatal(err)
		}
		if _, bad := insp["matcher_outcomes"]; bad {
			t.Fatal("list evidence_inspection must not include matcher_outcomes")
		}
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
	reqRaw := m["request_summary"]
	var reqSum map[string]json.RawMessage
	_ = json.Unmarshal(reqRaw, &reqSum)
	for _, k := range []string{"method", "url_short", "header_count", "body_byte_length"} {
		if _, ok := reqSum[k]; !ok {
			t.Fatalf("request_summary missing %q", k)
		}
	}
	resRaw := m["response_summary"]
	var resSum map[string]json.RawMessage
	_ = json.Unmarshal(resRaw, &resSum)
	for _, k := range []string{"status_code", "header_count", "body_byte_length"} {
		if _, ok := resSum[k]; !ok {
			t.Fatalf("response_summary missing %q", k)
		}
	}
}

func TestFindingsList_evidenceInspectionCompactCounts(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	evSum, serr := findings.MarshalEvidenceSummaryJSON(findings.EvidenceSummaryV1{
		MatcherOutcomes: []findings.MatcherOutcomeSummary{
			{Index: 0, Kind: "k0", Passed: true},
			{Index: 1, Kind: "k1", Passed: false},
		},
		DiffPoints: []string{"one"},
	})
	if serr != nil {
		t.Fatal(serr)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID:                 scan.ID,
		RuleID:                 "rule.x",
		Category:               "c",
		Severity:               findings.SeverityLow,
		RuleDeclaredConfidence: "low",
		AssessmentTier:         "tentative",
		Summary:                "s",
		EvidenceSummary:        evSum,
		BaselineExecutionID:    "b-1",
		MutatedExecutionID:     "m-1",
		Evidence:               storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?limit=10")
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
	if len(env.Items) != 1 {
		t.Fatalf("items %+v", env.Items)
	}
	ins := env.Items[0].EvidenceInspection
	if ins == nil || ins.MatcherPassed != 1 || ins.MatcherFailed != 1 || ins.MatcherTotal != 2 || ins.DiffPointCount != 1 {
		t.Fatalf("ins %+v", ins)
	}
	if h := env.Items[0].ComparisonHint; h == "" || !strings.Contains(h, "finding_detail_path") {
		t.Fatalf("comparison_hint %q", h)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(top["items"], &items); err != nil {
		t.Fatal(err)
	}
	var insp map[string]json.RawMessage
	if err := json.Unmarshal(items[0]["evidence_inspection"], &insp); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"matcher_outcomes", "baseline_execution_id", "mutated_execution_id"} {
		if _, bad := insp[forbidden]; bad {
			t.Fatalf("unexpected key %q in list evidence_inspection", forbidden)
		}
	}
}

func TestFindingsList_itemCoreFieldsMatchFindingDetail(t *testing.T) {
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
		RuleID:                 "rule.par",
		Category:               "cat",
		Severity:               findings.SeverityMedium,
		RuleDeclaredConfidence: "medium",
		AssessmentTier:         "confirmed",
		Summary:                "one line",
		EvidenceSummary:        evSum,
		ScanEndpointID:         "22222222-2222-2222-2222-222222222222",
		BaselineExecutionID:    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		MutatedExecutionID:     "mmmmmmmm-mmmm-mmmm-mmmm-mmmmmmmmmmmm",
		EvidenceURI:            "/v1/findings/x/evidence",
		Evidence:               storage.CreateEvidenceInput{},
	})
	if ferr != nil {
		t.Fatal(ferr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	respL, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	listBody, _ := io.ReadAll(respL.Body)
	_ = respL.Body.Close()
	if respL.StatusCode != http.StatusOK {
		t.Fatalf("list %d %s", respL.StatusCode, listBody)
	}
	var listEnv FindingListResponse
	if err = json.Unmarshal(listBody, &listEnv); err != nil {
		t.Fatal(err)
	}
	if len(listEnv.Items) != 1 {
		t.Fatalf("list items %+v", listEnv.Items)
	}
	li := listEnv.Items[0]

	respD, err := http.Get(srv.URL + "/v1/findings/" + f.ID)
	if err != nil {
		t.Fatal(err)
	}
	detailBody, _ := io.ReadAll(respD.Body)
	_ = respD.Body.Close()
	if respD.StatusCode != http.StatusOK {
		t.Fatalf("detail %d %s", respD.StatusCode, detailBody)
	}
	var fr FindingRead
	if err = json.Unmarshal(detailBody, &fr); err != nil {
		t.Fatal(err)
	}
	if li.ID != fr.ID || li.ScanID != fr.ScanID || li.RuleID != fr.RuleID || li.Category != fr.Category ||
		li.Severity != fr.Severity || li.RuleDeclaredConfidence != fr.RuleDeclaredConfidence ||
		li.AssessmentTier != fr.AssessmentTier || li.Summary != fr.Summary || li.EvidenceURI != fr.EvidenceURI ||
		li.ScanEndpointID != fr.ScanEndpointID || li.BaselineExecutionID != fr.BaselineExecutionID ||
		li.MutatedExecutionID != fr.MutatedExecutionID {
		t.Fatalf("list %+v detail %+v", li, fr)
	}
	wantDetail := "/v1/findings/" + f.ID
	wantList := "/v1/scans/" + scan.ID + "/findings"
	if li.FindingDetailPath != wantDetail || fr.FindingDetailPath != wantDetail || fr.FindingsListPath != wantList {
		t.Fatalf("paths list=%q detail=%q findings_list=%q want detail %q list %q", li.FindingDetailPath, fr.FindingDetailPath, fr.FindingsListPath, wantDetail, wantList)
	}
	if fr.EvidenceInspection == nil || li.EvidenceInspection == nil {
		t.Fatalf("expected inspections list=%v detail=%v", li.EvidenceInspection, fr.EvidenceInspection)
	}
	if li.EvidenceInspection.MatcherPassed != 1 || li.EvidenceInspection.MatcherFailed != 0 {
		t.Fatalf("list counts %+v", li.EvidenceInspection)
	}
	if len(fr.EvidenceInspection.MatcherOutcomes) != 1 || !fr.EvidenceInspection.MatcherOutcomes[0].Passed {
		t.Fatalf("detail outcomes %+v", fr.EvidenceInspection.MatcherOutcomes)
	}
}

func TestExecutionsList_summariesMatchExecutionDetail(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	eid, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID:              scan.ID,
		ScanEndpointID:      "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Phase:               engine.PhaseMutated,
		RuleID:              "rule.zed",
		CandidateKey:        "ck-9",
		RequestMethod:       "POST",
		RequestURL:          "https://example.com/long-url-path",
		RequestHeaders:      map[string]string{"X": "1"},
		RequestBody:         `{"a":1}`,
		ResponseStatus:      422,
		ResponseHeaders:     map[string]string{"Y": "2"},
		ResponseBody:        `err`,
		ResponseContentType: "application/problem+json",
		DurationMs:          42,
	})
	if ierr != nil {
		t.Fatal(ierr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	respL, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := io.ReadAll(respL.Body)
	_ = respL.Body.Close()
	if respL.StatusCode != http.StatusOK {
		t.Fatalf("list %d %s", respL.StatusCode, lb)
	}
	var listEnv ExecutionListResponse
	if err = json.Unmarshal(lb, &listEnv); err != nil {
		t.Fatal(err)
	}
	if len(listEnv.Items) != 1 {
		t.Fatal(listEnv.Items)
	}
	ei := listEnv.Items[0]

	respD, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions/" + eid)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := io.ReadAll(respD.Body)
	_ = respD.Body.Close()
	if respD.StatusCode != http.StatusOK {
		t.Fatalf("detail %d %s", respD.StatusCode, db)
	}
	var er ExecutionRead
	if err = json.Unmarshal(db, &er); err != nil {
		t.Fatal(err)
	}
	if ei.ID != er.ID || ei.Phase != er.Phase || ei.ExecutionKind != er.ExecutionKind ||
		ei.MutationRuleID != er.MutationRuleID || ei.CandidateKey != er.CandidateKey ||
		ei.ScanEndpointID != er.ScanEndpointID {
		t.Fatalf("list %+v detail %+v", ei, er)
	}
	if ei.RequestSummary != er.RequestSummary || ei.ResponseSummary != er.ResponseSummary {
		t.Fatalf("summary mismatch list=%+v detail=%+v", ei.RequestSummary, er.ResponseSummary)
	}
	if ei.DurationMs != er.DurationMs {
		t.Fatalf("duration list=%d detail=%d", ei.DurationMs, er.DurationMs)
	}
	wantExec := "/v1/scans/" + scan.ID + "/executions/" + eid
	wantExecList := "/v1/scans/" + scan.ID + "/executions"
	if ei.ExecutionDetailPath != wantExec || er.ExecutionDetailPath != wantExec || er.ExecutionsListPath != wantExecList {
		t.Fatalf("paths list=%q detail=%q exec_list=%q", ei.ExecutionDetailPath, er.ExecutionDetailPath, er.ExecutionsListPath)
	}
}
