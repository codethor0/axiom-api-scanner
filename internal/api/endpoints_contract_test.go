package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

var endpointListItemKeys = []string{
	"id",
	"scan_id",
	"method",
	"path_template",
	"request_body_json",
	"created_at",
	"declares_openapi_security",
}

var endpointSummaryKeys = []string{
	"baseline_executions_recorded",
	"mutation_executions_recorded",
	"findings_recorded",
}

var endpointListMetaKeys = []string{"limit", "sort", "order", "has_more"}

func TestContract_endpointList_wireEnvelope(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{
		{Method: "GET", Path: "/a", OperationID: "op.a"},
		{Method: "POST", Path: "/b/{id}", SecuritySchemeHints: []string{"Bearer"}, RequestBodyJSON: true},
	}); rerr != nil {
		t.Fatal(rerr)
	}
	eps, err := mem.ListScanEndpoints(ctx, scan.ID, storage.EndpointListFilter{})
	if err != nil || len(eps) != 2 {
		t.Fatal(eps, err)
	}
	epID := eps[0].ID
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: epID, Phase: engine.PhaseBaseline,
		RequestMethod: "GET", RequestURL: "http://x/a", ResponseStatus: 200,
	}); ierr != nil {
		t.Fatal(ierr)
	}
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID: scan.ID, ScanEndpointID: epID, Phase: engine.PhaseMutated, RuleID: "r1",
		RequestMethod: "GET", RequestURL: "http://x/a", ResponseStatus: 200,
	}); ierr != nil {
		t.Fatal(ierr)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "r1", Category: "c", Severity: findings.SeverityLow,
		AssessmentTier: "confirmed", Summary: "s", ScanEndpointID: epID,
		BaselineExecutionID: "b1", MutatedExecutionID: "m1",
		Evidence:              storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}

	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	var env EndpointListResponse
	if derr := json.NewDecoder(resp.Body).Decode(&env); derr != nil {
		t.Fatal(derr)
	}
	if env.Items == nil {
		t.Fatal("want items non-nil slice")
	}
	metaObj, err := json.Marshal(env.Meta)
	if err != nil {
		t.Fatal(err)
	}
	var metaMap map[string]json.RawMessage
	if err := json.Unmarshal(metaObj, &metaMap); err != nil {
		t.Fatal(err)
	}
	for _, k := range endpointListMetaKeys {
		if _, ok := metaMap[k]; !ok {
			t.Fatalf("meta missing key %q", k)
		}
	}
	if env.Meta.Limit != storage.DefaultListLimit || env.Meta.Sort != storage.EndpointListSortPath || env.Meta.Order != storage.ListSortAsc {
		t.Fatalf("meta %+v", env.Meta)
	}
	if env.Meta.HasMore {
		t.Fatal("expected has_more false")
	}
	if env.Meta.NextCursor != "" {
		t.Fatal("unexpected next_cursor on first page")
	}
	if len(env.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(env.Items))
	}
	for _, it := range env.Items {
		obj, err := json.Marshal(it)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(obj, &m); err != nil {
			t.Fatal(err)
		}
		for _, k := range endpointListItemKeys {
			if _, ok := m[k]; !ok {
				t.Fatalf("missing key %q in %s", k, obj)
			}
		}
		if _, bad := m["investigation"]; bad {
			t.Fatalf("list item must not include investigation: %s", obj)
		}
		if it.Summary == nil {
			t.Fatal("expected summary with default include_summary")
		}
		sumObj, ok := m["summary"]
		if !ok {
			t.Fatal("missing summary")
		}
		var sm map[string]int
		if err := json.Unmarshal(sumObj, &sm); err != nil {
			t.Fatal(err)
		}
		for _, k := range endpointSummaryKeys {
			if _, ok := sm[k]; !ok {
				t.Fatalf("summary missing %q", k)
			}
		}
	}

	var got *EndpointRead
	for i := range env.Items {
		if env.Items[i].ID == epID {
			got = &env.Items[i]
			break
		}
	}
	if got == nil {
		t.Fatal("endpoint not in list")
	}
	if got.Summary.BaselineExecutionsRecorded != 1 || got.Summary.MutationExecutionsRecorded != 1 || got.Summary.FindingsRecorded != 1 {
		t.Fatalf("summary %+v", got.Summary)
	}
}

func TestContract_endpointList_includeSummaryFalseOmitsSummary(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/x"}}); rerr != nil {
		t.Fatal(rerr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints?include_summary=false")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var env EndpointListResponse
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Items) != 1 {
		t.Fatalf("want 1 item, got %s", body)
	}
	if env.Items[0].Summary != nil {
		t.Fatalf("unexpected summary %+v", env.Items[0].Summary)
	}
	if strings.Contains(string(body), `"summary"`) {
		t.Fatalf("response should omit summary key: %s", body)
	}
	if env.Meta.Limit != storage.DefaultListLimit {
		t.Fatalf("meta %+v", env.Meta)
	}
}

func TestContract_endpointList_filterMethodAndSecurity(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{
		{Method: "GET", Path: "/pub"},
		{Method: "GET", Path: "/sec", SecuritySchemeHints: []string{"bearer"}},
	}); rerr != nil {
		t.Fatal(rerr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints?method=GET&declares_security=true&include_summary=false")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var env EndpointListResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if len(env.Items) != 1 || !strings.Contains(env.Items[0].PathTemplate, "/sec") {
		t.Fatalf("got %+v", env.Items)
	}
	if env.Items[0].DeclaresOpenAPISecurity != true {
		t.Fatal(env.Items[0])
	}
	if env.Meta.Sort != storage.EndpointListSortPath {
		t.Fatal(env.Meta)
	}
}

func TestContract_endpointList_keysetSecondPage(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	specs := []engine.EndpointSpec{
		{Method: "GET", Path: "/z"},
		{Method: "GET", Path: "/a"},
		{Method: "POST", Path: "/a"},
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, specs); rerr != nil {
		t.Fatal(rerr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	base := srv.URL + "/v1/scans/" + scan.ID + "/endpoints?include_summary=false&limit=2&sort=path&order=asc"

	resp1, err := http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp1.Body.Close() }()
	var first EndpointListResponse
	if derr := json.NewDecoder(resp1.Body).Decode(&first); derr != nil {
		t.Fatal(derr)
	}
	if len(first.Items) != 2 || !first.Meta.HasMore || first.Meta.NextCursor == "" {
		t.Fatalf("first page: %+v meta=%+v", first.Items, first.Meta)
	}
	if first.Items[0].PathTemplate != "/a" || first.Items[0].Method != "GET" {
		t.Fatalf("order want GET /a first, got %s %s", first.Items[0].Method, first.Items[0].PathTemplate)
	}
	resp2, err := http.Get(base + "&cursor=" + url.QueryEscape(first.Meta.NextCursor))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	var second EndpointListResponse
	if derr := json.NewDecoder(resp2.Body).Decode(&second); derr != nil {
		t.Fatal(derr)
	}
	if len(second.Items) != 1 {
		t.Fatalf("second page len %d", len(second.Items))
	}
	if second.Meta.HasMore || second.Meta.NextCursor != "" {
		t.Fatalf("second meta %+v", second.Meta)
	}
	if second.Items[0].PathTemplate != "/z" {
		t.Fatalf("got %+v", second.Items[0])
	}
}

func TestContract_endpointList_invalidQuery(t *testing.T) {
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

	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints?include_summary=maybe")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestContract_endpointList_invalidSortAndOffset(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	base := srv.URL + "/v1/scans/" + scan.ID + "/endpoints"

	r1, err := http.Get(base + "?sort=severity")
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Body.Close()
	if r1.StatusCode != http.StatusBadRequest {
		t.Fatalf("sort severity: status %d", r1.StatusCode)
	}
	r2, err := http.Get(base + "?offset=1")
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusBadRequest {
		t.Fatalf("offset: status %d", r2.StatusCode)
	}
}

func TestContract_endpointList_badCursor(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints?cursor=not-a-valid-cursor")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestContract_endpointList_cursorRequiresMatchingSort(t *testing.T) {
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
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	cur := ""
	{
		rpath, gerr := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints?limit=1&sort=path&order=asc&include_summary=false")
		if gerr != nil {
			t.Fatal(gerr)
		}
		var env EndpointListResponse
		if derr := json.NewDecoder(rpath.Body).Decode(&env); derr != nil {
			t.Fatal(derr)
		}
		_ = rpath.Body.Close()
		cur = env.Meta.NextCursor
		if cur == "" {
			t.Fatal("want next_cursor")
		}
	}
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/endpoints?limit=1&sort=method&order=asc&include_summary=false&cursor=" + url.QueryEscape(cur))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
