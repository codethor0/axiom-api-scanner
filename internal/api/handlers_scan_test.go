package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chomechomekitchen/axiom-api-scanner/internal/engine"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/findings"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/storage"
	"github.com/google/uuid"
)

type memRepositories struct {
	mu          sync.Mutex
	scans       map[string]engine.Scan
	byScan      map[string][]findings.Finding
	byFind      map[string]findings.Finding
	evidence    map[string]findings.EvidenceArtifact
	endpoints   map[string][]engine.ScanEndpoint
	execRecords map[string]engine.ExecutionRecord
}

func newMemRepositories() *memRepositories {
	return &memRepositories{
		scans:       make(map[string]engine.Scan),
		byScan:      make(map[string][]findings.Finding),
		byFind:      make(map[string]findings.Finding),
		evidence:    make(map[string]findings.EvidenceArtifact),
		endpoints:   make(map[string][]engine.ScanEndpoint),
		execRecords: make(map[string]engine.ExecutionRecord),
	}
}

func (m *memRepositories) CreateScan(_ context.Context, in storage.CreateScanInput) (engine.Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.NewString()
	now := time.Now().UTC()
	auth := in.AuthHeaders
	if auth == nil {
		auth = map[string]string{}
	}
	s := engine.Scan{
		ID:                     id,
		Status:                 engine.ScanQueued,
		TargetLabel:            in.TargetLabel,
		SafetyMode:             in.SafetyMode,
		AllowFullExecution:     in.AllowFullExecution,
		BaseURL:                in.BaseURL,
		AuthHeaders:            auth,
		BaselineEndpointsTotal: 0,
		BaselineEndpointsDone:  0,
		CreatedAt:              now,
		UpdatedAt:                now,
	}
	m.scans[id] = s
	return s, nil
}

func (m *memRepositories) PatchScanTarget(_ context.Context, id string, in storage.PatchScanTargetInput) (engine.Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.scans[id]
	if !ok {
		return engine.Scan{}, storage.ErrNotFound
	}
	if in.BaseURL != nil {
		s.BaseURL = *in.BaseURL
	}
	if in.ReplaceAuth {
		if in.AuthHeaders != nil {
			s.AuthHeaders = in.AuthHeaders
		} else {
			s.AuthHeaders = map[string]string{}
		}
	}
	s.UpdatedAt = time.Now().UTC()
	m.scans[id] = s
	return s, nil
}

func (m *memRepositories) UpdateBaselineState(_ context.Context, scanID string, st storage.BaselineState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.scans[scanID]
	if !ok {
		return storage.ErrNotFound
	}
	s.BaselineRunStatus = st.Status
	s.BaselineRunError = st.Error
	s.BaselineEndpointsTotal = st.Total
	s.BaselineEndpointsDone = st.Done
	s.UpdatedAt = time.Now().UTC()
	m.scans[scanID] = s
	return nil
}

func (m *memRepositories) ReplaceScanEndpoints(_ context.Context, scanID string, specs []engine.EndpointSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.scans[scanID]; !ok {
		return storage.ErrNotFound
	}
	var rows []engine.ScanEndpoint
	for _, sp := range specs {
		rows = append(rows, engine.ScanEndpoint{
			ID:                   uuid.NewString(),
			ScanID:               scanID,
			Method:               sp.Method,
			PathTemplate:         sp.Path,
			OperationID:          sp.OperationID,
			SecuritySchemeHints:  append([]string(nil), sp.SecuritySchemeHints...),
			RequestContentTypes:  append([]string(nil), sp.RequestContentTypes...),
			ResponseContentTypes: append([]string(nil), sp.ResponseContentTypes...),
			RequestBodyJSON:      sp.RequestBodyJSON,
			CreatedAt:            time.Now().UTC(),
		})
	}
	m.endpoints[scanID] = rows
	return nil
}

func (m *memRepositories) ListScanEndpoints(_ context.Context, scanID string) ([]engine.ScanEndpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]engine.ScanEndpoint(nil), m.endpoints[scanID]...), nil
}

func (m *memRepositories) InsertExecutionRecord(_ context.Context, rec engine.ExecutionRecord) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.NewString()
	rec.ID = id
	rec.CreatedAt = time.Now().UTC()
	m.execRecords[id] = rec
	return id, nil
}

func (m *memRepositories) GetLatestExecution(_ context.Context, scanID, scanEndpointID string, phase engine.ExecutionPhase) (engine.ExecutionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best engine.ExecutionRecord
	var found bool
	for _, rec := range m.execRecords {
		if rec.ScanID != scanID || rec.ScanEndpointID != scanEndpointID || rec.Phase != phase {
			continue
		}
		if !found || rec.CreatedAt.After(best.CreatedAt) {
			best = rec
			found = true
		}
	}
	if !found {
		return engine.ExecutionRecord{}, storage.ErrNotFound
	}
	return best, nil
}

func (m *memRepositories) ListExecutions(_ context.Context, scanID string, filter storage.ExecutionListFilter) ([]engine.ExecutionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var list []engine.ExecutionRecord
	for _, rec := range m.execRecords {
		if rec.ScanID != scanID {
			continue
		}
		if filter.Phase != "" && string(rec.Phase) != filter.Phase {
			continue
		}
		if filter.ScanEndpointID != "" && rec.ScanEndpointID != filter.ScanEndpointID {
			continue
		}
		if filter.RuleID != "" && rec.RuleID != filter.RuleID {
			continue
		}
		if filter.ResponseStatus > 0 && rec.ResponseStatus != filter.ResponseStatus {
			continue
		}
		list = append(list, rec)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.Before(list[j].CreatedAt)
	})
	return list, nil
}

func (m *memRepositories) GetExecution(_ context.Context, scanID, executionID string) (engine.ExecutionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.execRecords[executionID]
	if !ok || rec.ScanID != scanID {
		return engine.ExecutionRecord{}, storage.ErrNotFound
	}
	return rec, nil
}

func (m *memRepositories) UpdateMutationState(_ context.Context, scanID string, st storage.MutationState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.scans[scanID]
	if !ok {
		return storage.ErrNotFound
	}
	s.MutationRunStatus = st.Status
	s.MutationRunError = st.Error
	s.MutationCandidatesTotal = st.Total
	s.MutationCandidatesDone = st.Done
	s.UpdatedAt = time.Now().UTC()
	m.scans[scanID] = s
	return nil
}

func (m *memRepositories) CreateFinding(_ context.Context, in storage.CreateFindingInput) (findings.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.NewString()
	now := time.Now().UTC()
	evidenceURI := in.EvidenceURI
	if evidenceURI == "" {
		evidenceURI = "/v1/findings/" + id + "/evidence"
	}
	tier := in.AssessmentTier
	if tier == "" {
		tier = "tentative"
	}
	f := findings.Finding{
		ID:                     id,
		ScanID:                 in.ScanID,
		RuleID:                 in.RuleID,
		Category:               in.Category,
		Severity:               in.Severity,
		RuleDeclaredConfidence: in.RuleDeclaredConfidence,
		AssessmentTier:         tier,
		Summary:                in.Summary,
		EvidenceURI:            evidenceURI,
		ScanEndpointID:         in.ScanEndpointID,
		BaselineExecutionID:    in.BaselineExecutionID,
		MutatedExecutionID:     in.MutatedExecutionID,
		CreatedAt:              now,
	}
	if len(in.EvidenceSummary) > 0 {
		f.EvidenceSummary = in.EvidenceSummary
	}
	m.byFind[id] = f
	m.byScan[in.ScanID] = append(m.byScan[in.ScanID], f)
	m.evidence[id] = findings.EvidenceArtifact{
		ID:              uuid.NewString(),
		FindingID:       id,
		BaselineRequest: in.Evidence.BaselineRequest,
		MutatedRequest:  in.Evidence.MutatedRequest,
		BaselineBody:    in.Evidence.BaselineBody,
		MutatedBody:     in.Evidence.MutatedBody,
		DiffSummary:     in.Evidence.DiffSummary,
		CreatedAt:       now,
	}
	s, ok := m.scans[in.ScanID]
	if !ok {
		return findings.Finding{}, storage.ErrNotFound
	}
	s.FindingsCount++
	m.scans[in.ScanID] = s
	return f, nil
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

func (m *memRepositories) ListByScanID(_ context.Context, scanID string, filter storage.FindingListFilter) ([]findings.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []findings.Finding
	for _, f := range m.byScan[scanID] {
		if filter.AssessmentTier != "" && f.AssessmentTier != filter.AssessmentTier {
			continue
		}
		if filter.Severity != "" && string(f.Severity) != filter.Severity {
			continue
		}
		if filter.RuleDeclaredConfidence != "" && f.RuleDeclaredConfidence != filter.RuleDeclaredConfidence {
			continue
		}
		out = append(out, f)
	}
	return out, nil
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

func testHandler(mem *memRepositories) *Handler {
	return &Handler{
		RulesDir:    "",
		Scans:       mem,
		ScanTargets: mem,
		Endpoints:   mem,
		Executions:  mem,
		Findings:    mem,
		Evidence:    mem,
		Baseline:    nil,
	}
}

func TestListExecutions_returnsExecutionReadEnvelope(t *testing.T) {
	mem := newMemRepositories()
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	body := `{"target_label":"t","safety_mode":"safe"}`
	cr, err := http.Post(srv.URL+"/v1/scans", "application/json", strings.NewReader(body))
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
	var list []ExecutionRead
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if list == nil {
		t.Fatal("want non-nil slice")
	}
}

func TestCreateScan_fullModeRequiresOptIn(t *testing.T) {
	mem := newMemRepositories()
	h := testHandler(mem)
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)

	body := map[string]any{
		"target_label": "t",
		"safety_mode":  "full",
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
	h := testHandler(mem)
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
	h := testHandler(mem)
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
