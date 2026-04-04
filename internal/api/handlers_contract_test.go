package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/executor/baseline"
	"github.com/codethor0/axiom-api-scanner/internal/executor/mutation"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

func testHandlerWithExecutors(mem *memRepositories) *Handler {
	h := testHandler(mem)
	h.Baseline = baseline.NewRunner(mem)
	h.Mutations = mutation.NewRunner(mem)
	return h
}

func TestAPI_patchScan_updatesBaseURL(t *testing.T) {
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

	patch := `{"base_url":"https://example.com/api"}`
	req, err := http.NewRequest(http.MethodPatch, srv.URL+"/v1/scans/"+scan.ID, strings.NewReader(patch))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var got engine.Scan
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.BaseURL != "https://example.com/api" {
		t.Fatalf("got %+v", got)
	}
}

func TestAPI_patchScan_invalidUUID(t *testing.T) {
	mem := newMemRepositories()
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPatch, srv.URL+"/v1/scans/not-a-uuid", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestAPI_listExecutions_empty(t *testing.T) {
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

	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var body ExecutionListResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Items == nil || len(body.Items) != 0 || body.Meta.HasMore || body.Meta.NextCursor != "" {
		t.Fatalf("got %+v", body)
	}
	if body.Meta.Limit != 50 || body.Meta.Sort != "created_at" || body.Meta.Order != "asc" {
		t.Fatalf("meta %+v", body.Meta)
	}
	if body.ScanNavigation != NewScanListNavigation(scan.ID) {
		t.Fatalf("scan_navigation %+v", body.ScanNavigation)
	}
}

func TestAPI_getExecution_invalidPathUUIDs(t *testing.T) {
	mem := newMemRepositories()
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/not-a-uuid/executions/00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("scan id status %d", resp.StatusCode)
	}
	cr, err := http.Post(srv.URL+"/v1/scans", "application/json", strings.NewReader(`{"target_label":"t","safety_mode":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	var scan engine.Scan
	_ = json.NewDecoder(cr.Body).Decode(&scan)
	_ = cr.Body.Close()
	resp2, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions/not-a-uuid")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("execution id status %d", resp2.StatusCode)
	}
}

func TestAPI_getExecution_scanNotFound(t *testing.T) {
	mem := newMemRepositories()
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/00000000-0000-0000-0000-000000000099/executions/00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestAPI_getExecution_notFound(t *testing.T) {
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

	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions/" + "00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestAPI_runBaseline_serviceUnavailableWithoutRunner(t *testing.T) {
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

	resp, err := http.Post(srv.URL+"/v1/scans/"+scan.ID+"/executions/baseline", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestAPI_runMutations_requiresBaselineSuccess(t *testing.T) {
	ruleDir := t.TempDir()
	rulePath := filepath.Join(ruleDir, "contract.yaml")
	content := `id: test.contract.mutations
name: contract
category: test
severity: low
confidence: low
safety:
  mode: safe
  destructive: false
target:
  methods: [GET]
  where: path
mutations:
  - kind: replace_path_param
    param: id
    from: a
    to: b
matchers:
  - kind: status_code_unchanged
references:
  - https://example.com
`
	if err := os.WriteFile(rulePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	mem := newMemRepositories()
	h := testHandlerWithExecutors(mem)
	h.RulesDir = ruleDir
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)

	cr, err := http.Post(srv.URL+"/v1/scans", "application/json", strings.NewReader(`{"target_label":"t","safety_mode":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	var scan engine.Scan
	_ = json.NewDecoder(cr.Body).Decode(&scan)
	_ = cr.Body.Close()

	patch := `{"base_url":"http://127.0.0.1:9"}`
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/v1/scans/"+scan.ID, strings.NewReader(patch))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}

	openapiBody := []byte(`openapi: 3.0.3
info:
  title: T
  version: "1.0"
paths:
  /items/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
`)
	im, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/scans/"+scan.ID+"/specs/openapi", bytes.NewReader(openapiBody))
	if err != nil {
		t.Fatal(err)
	}
	im.Header.Set("Content-Type", "application/yaml")
	resp2, err := http.DefaultClient.Do(im)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("import status %d", resp2.StatusCode)
	}

	mr, err := http.Post(srv.URL+"/v1/scans/"+scan.ID+"/executions/mutations", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mr.Body.Close() }()
	if mr.StatusCode != http.StatusOK {
		t.Fatalf("status %d", mr.StatusCode)
	}
	var env struct {
		Result struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"result"`
	}
	if err := json.NewDecoder(mr.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Result.Status != "failed" || env.Result.Error != "baseline_must_succeed_first" {
		t.Fatalf("%+v", env.Result)
	}
}

func TestAPI_importOpenAPI_twice_replacesEndpoints(t *testing.T) {
	mem := newMemRepositories()
	h := testHandler(mem)
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)

	cr, err := http.Post(srv.URL+"/v1/scans", "application/json", strings.NewReader(`{"target_label":"t","safety_mode":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	var scan engine.Scan
	_ = json.NewDecoder(cr.Body).Decode(&scan)
	_ = cr.Body.Close()

	spec1 := []byte(`openapi: 3.0.3
info:
  title: T
  version: "1.0"
paths:
  /a:
    get:
      responses:
        "200":
          description: ok
`)
	req1, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/scans/"+scan.ID+"/specs/openapi", bytes.NewReader(spec1))
	req1.Header.Set("Content-Type", "application/yaml")
	resp1, _ := http.DefaultClient.Do(req1)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatal(resp1.StatusCode)
	}

	list1, err := h.Endpoints.ListScanEndpoints(context.Background(), scan.ID, storage.EndpointListFilter{})
	if err != nil || len(list1) != 1 || list1[0].PathTemplate != "/a" {
		t.Fatal(list1, err)
	}
	oldID := list1[0].ID

	spec2 := []byte(`openapi: 3.0.3
info:
  title: T
  version: "1.0"
paths:
  /b:
    get:
      responses:
        "200":
          description: ok
`)
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/scans/"+scan.ID+"/specs/openapi", bytes.NewReader(spec2))
	req2.Header.Set("Content-Type", "application/yaml")
	resp2, _ := http.DefaultClient.Do(req2)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatal(resp2.StatusCode)
	}

	list2, err := h.Endpoints.ListScanEndpoints(context.Background(), scan.ID, storage.EndpointListFilter{})
	if err != nil || len(list2) != 1 || list2[0].PathTemplate != "/b" {
		t.Fatal(list2, err)
	}
	if list2[0].ID == oldID {
		t.Fatalf("endpoint id should change after replace, still %s", oldID)
	}
}

func TestAPI_getFindingAndEvidence_notFound(t *testing.T) {
	mem := newMemRepositories()
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/findings/00000000-0000-0000-0000-000000000099")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}

	respe, err := http.Get(srv.URL + "/v1/findings/00000000-0000-0000-0000-000000000099/evidence")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = respe.Body.Close() }()
	if respe.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", respe.StatusCode)
	}
}
