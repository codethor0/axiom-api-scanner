package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/google/uuid"
)

type memRepositories struct {
	mu       sync.Mutex
	scans    map[string]engine.Scan
	byScan   map[string][]findings.Finding
	byFind   map[string]findings.Finding
	evidence map[string]findings.EvidenceArtifact
}

func newMemRepositories() *memRepositories {
	return &memRepositories{
		scans:    make(map[string]engine.Scan),
		byScan:   make(map[string][]findings.Finding),
		byFind:   make(map[string]findings.Finding),
		evidence: make(map[string]findings.EvidenceArtifact),
	}
}

func (m *memRepositories) CreateScan(_ context.Context, in storage.CreateScanInput) (engine.Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.NewString()
	now := time.Now().UTC()
	s := engine.Scan{
		ID:                 id,
		Status:             engine.ScanQueued,
		TargetLabel:        in.TargetLabel,
		SafetyMode:         in.SafetyMode,
		AllowFullExecution: in.AllowFullExecution,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	m.scans[id] = s
	return s, nil
}

func (m *memRepositories) GetScan(_ context.Context, id string) (engine.Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.scans[id]
	if !ok {
		return engine.Scan{}, storage.ErrNotFound
	}
	return s, nil
}

func (m *memRepositories) ApplyControl(_ context.Context, id string, action storage.ScanControlAction) (engine.Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.scans[id]
	if !ok {
		return engine.Scan{}, storage.ErrNotFound
	}
	next, err := nextScanStatusMem(s.Status, action)
	if err != nil {
		return engine.Scan{}, err
	}
	s.Status = next
	s.UpdatedAt = time.Now().UTC()
	m.scans[id] = s
	return s, nil
}

func nextScanStatusMem(cur engine.ScanStatus, action storage.ScanControlAction) (engine.ScanStatus, error) {
	switch action {
	case storage.ScanControlStart:
		switch cur {
		case engine.ScanQueued, engine.ScanPaused:
			return engine.ScanRunning, nil
		}
	case storage.ScanControlPause:
		if cur == engine.ScanRunning {
			return engine.ScanPaused, nil
		}
	case storage.ScanControlCancel:
		switch cur {
		case engine.ScanQueued, engine.ScanRunning, engine.ScanPaused:
			return engine.ScanCanceled, nil
		}
	}
	return "", storage.ErrInvalidTransition
}

func (m *memRepositories) ListByScanID(_ context.Context, scanID string) ([]findings.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]findings.Finding(nil), m.byScan[scanID]...), nil
}

func (m *memRepositories) GetByID(_ context.Context, id string) (findings.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.byFind[id]
	if !ok {
		return findings.Finding{}, storage.ErrNotFound
	}
	return f, nil
}

func (m *memRepositories) GetArtifactByFindingID(_ context.Context, findingID string) (findings.EvidenceArtifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.evidence[findingID]
	if !ok {
		return findings.EvidenceArtifact{}, storage.ErrNotFound
	}
	return e, nil
}

func TestCreateScan_fullModeRequiresOptIn(t *testing.T) {
	mem := newMemRepositories()
	h := &Handler{Scans: mem, Findings: mem, Evidence: mem}
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)

	body := map[string]any{
		"target_label": "t",
		"safety_mode":  "full",
		// allow_full_execution omitted
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/v1/scans", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestCreateScan_persistsAndGets(t *testing.T) {
	mem := newMemRepositories()
	h := &Handler{Scans: mem, Findings: mem, Evidence: mem}
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)

	create := []byte(`{"target_label":"api1","safety_mode":"safe","allow_full_execution":false}`)
	resp, err := http.Post(srv.URL+"/v1/scans", "application/json", bytes.NewReader(create))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var scan engine.Scan
	if derr := json.NewDecoder(resp.Body).Decode(&scan); derr != nil {
		t.Fatal(derr)
	}
	if scan.ID == "" || scan.Status != engine.ScanQueued {
		t.Fatalf("scan %+v", scan)
	}

	getResp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status %d", getResp.StatusCode)
	}
}

func TestControlScan_invalidAction(t *testing.T) {
	mem := newMemRepositories()
	h := &Handler{Scans: mem, Findings: mem, Evidence: mem}
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)

	create := []byte(`{"target_label":"api1","safety_mode":"safe"}`)
	cr, err := http.Post(srv.URL+"/v1/scans", "application/json", bytes.NewReader(create))
	if err != nil {
		t.Fatal(err)
	}
	var scan engine.Scan
	_ = json.NewDecoder(cr.Body).Decode(&scan)
	_ = cr.Body.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/scans/"+scan.ID+"/control", bytes.NewReader([]byte(`{"action":"destroy"}`)))
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
