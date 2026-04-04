package baseline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/google/uuid"
)

type memRun struct {
	mu         sync.Mutex
	scans      map[string]engine.Scan
	endpoints  map[string][]engine.ScanEndpoint
	records    map[string]engine.ExecutionRecord
	recOrder   []string
	baselineSt map[string]storage.BaselineState
}

func newMemRun() *memRun {
	return &memRun{
		scans:      make(map[string]engine.Scan),
		endpoints:  make(map[string][]engine.ScanEndpoint),
		records:    make(map[string]engine.ExecutionRecord),
		baselineSt: make(map[string]storage.BaselineState),
	}
}

func (m *memRun) GetScan(_ context.Context, id string) (engine.Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.scans[id]
	if !ok {
		return engine.Scan{}, storage.ErrNotFound
	}
	return s, nil
}

func (m *memRun) ListScanEndpoints(_ context.Context, scanID string, filter storage.EndpointListFilter) ([]engine.ScanEndpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []engine.ScanEndpoint
	for _, ep := range m.endpoints[scanID] {
		if storage.ScanEndpointMatchesListFilter(ep, filter) {
			out = append(out, ep)
		}
	}
	return out, nil
}

func (m *memRun) InsertExecutionRecord(_ context.Context, rec engine.ExecutionRecord) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.NewString()
	rec.ID = id
	m.records[id] = rec
	m.recOrder = append(m.recOrder, id)
	return id, nil
}

func (m *memRun) UpdateBaselineState(_ context.Context, scanID string, st storage.BaselineState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.baselineSt[scanID] = st
	return nil
}

func TestRunner_Get_success(t *testing.T) {
	srv := httptestServer(t)
	t.Cleanup(srv.Close)

	mem := newMemRun()
	id := uuid.NewString()
	mem.scans[id] = engine.Scan{
		ID:      id,
		BaseURL: srv.URL,
		AuthHeaders: map[string]string{
			"X-Test": "1",
		},
	}
	mem.endpoints[id] = []engine.ScanEndpoint{
		{ID: "e1", Method: "GET", PathTemplate: "/ping"},
	}

	r := NewRunner(mem)
	res, err := r.Run(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "succeeded" || res.EndpointsExecuted != 1 {
		t.Fatalf("%+v", res)
	}
	if len(res.ExecutionRecordIDs) != 1 {
		t.Fatal(res)
	}
	rec := mem.records[res.ExecutionRecordIDs[0]]
	if rec.ResponseStatus != http.StatusOK {
		t.Fatalf("%+v", rec)
	}
	if rec.RequestHeaders["X-Test"] != "1" {
		t.Fatalf("%+v", rec.RequestHeaders)
	}
}

func TestRunner_redactsAuthorizationInStoredRecord(t *testing.T) {
	srv := httptestServer(t)
	t.Cleanup(srv.Close)

	mem := newMemRun()
	id := uuid.NewString()
	mem.scans[id] = engine.Scan{
		ID:      id,
		BaseURL: srv.URL,
		AuthHeaders: map[string]string{
			"Authorization": "Bearer secret-token",
		},
	}
	mem.endpoints[id] = []engine.ScanEndpoint{
		{ID: "e1", Method: "GET", PathTemplate: "/ping"},
	}

	r := NewRunner(mem)
	_, err := r.Run(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(mem.recOrder) != 1 {
		t.Fatal(mem.recOrder)
	}
	rec := mem.records[mem.recOrder[0]]
	if rec.RequestHeaders["Authorization"] != "[REDACTED]" {
		t.Fatalf("want redacted, got %q", rec.RequestHeaders["Authorization"])
	}
}

func TestRunner_requires_base_url(t *testing.T) {
	mem := newMemRun()
	id := uuid.NewString()
	mem.scans[id] = engine.Scan{ID: id, BaseURL: ""}
	r := NewRunner(mem)
	_, err := r.Run(context.Background(), id)
	if err == nil {
		t.Fatal("expected error")
	}
}

func httptestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ping" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	}))
}
