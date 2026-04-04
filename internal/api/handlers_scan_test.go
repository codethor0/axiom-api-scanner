package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
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
		RunPhase:               engine.PhasePlanned,
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

func (m *memRepositories) GetMutationByCandidate(_ context.Context, scanID, scanEndpointID, ruleID, candidateKey string) (engine.ExecutionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if candidateKey == "" {
		return engine.ExecutionRecord{}, storage.ErrNotFound
	}
	var best engine.ExecutionRecord
	var found bool
	for _, rec := range m.execRecords {
		if rec.ScanID != scanID || rec.ScanEndpointID != scanEndpointID || rec.Phase != engine.PhaseMutated ||
			rec.RuleID != ruleID || rec.CandidateKey != candidateKey {
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
		if list[i].CreatedAt.Equal(list[j].CreatedAt) {
			return list[i].ID < list[j].ID
		}
		return list[i].CreatedAt.Before(list[j].CreatedAt)
	})
	return list, nil
}

func (m *memRepositories) ListExecutionsPage(_ context.Context, scanID string, filter storage.ExecutionListFilter, opts storage.ExecutionListPageOptions) (storage.ExecutionListPage, error) {
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
	o := strings.TrimSpace(opts.SortOrder)
	if o == "" {
		o = storage.ListSortAsc
	}
	asc := strings.EqualFold(o, storage.ListSortAsc)
	sort.SliceStable(list, func(i, j int) bool {
		return storage.ExecutionLess(list[i], list[j], opts.SortField, asc)
	})
	start := 0
	if strings.TrimSpace(opts.Cursor) != "" {
		ts, id, pOrd, sOrd, err := storage.DecodeListCursor(opts.Cursor, opts.SortField, o)
		if err != nil {
			return storage.ExecutionListPage{}, err
		}
		if sOrd != nil {
			return storage.ExecutionListPage{}, storage.ErrInvalidListCursor
		}
		found := false
		for i := range list {
			if storage.ExecutionKeysetAfter(list[i], ts, id, pOrd, opts.SortField, asc) {
				start = i
				found = true
				break
			}
		}
		if !found {
			start = len(list)
		}
	}
	end := start + opts.Limit + 1
	if end > len(list) {
		end = len(list)
	}
	page := list[start:end]
	hasMore := len(page) > opts.Limit
	if hasMore {
		page = page[:opts.Limit]
	}
	out := storage.ExecutionListPage{Records: page, HasMore: hasMore}
	if hasMore && len(page) > 0 {
		cur, err := storage.EncodeExecutionPageCursor(page[len(page)-1], opts.SortField, o)
		if err != nil {
			return storage.ExecutionListPage{}, err
		}
		out.NextCursor = cur
	}
	return out, nil
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

func (m *memRepositories) GetByEvidenceTuple(_ context.Context, scanID, ruleID, scanEndpointID, baselineExecutionID, mutatedExecutionID string) (findings.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.byScan[scanID] {
		if f.RuleID == ruleID && f.ScanEndpointID == scanEndpointID &&
			f.BaselineExecutionID == baselineExecutionID && f.MutatedExecutionID == mutatedExecutionID {
			return f, nil
		}
	}
	return findings.Finding{}, storage.ErrNotFound
}

func (m *memRepositories) CreateFinding(_ context.Context, in storage.CreateFindingInput) (findings.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.byScan[in.ScanID] {
		if f.RuleID == in.RuleID && f.ScanEndpointID == in.ScanEndpointID &&
			f.BaselineExecutionID == in.BaselineExecutionID && f.MutatedExecutionID == in.MutatedExecutionID {
			return findings.Finding{}, storage.ErrDuplicateFinding
		}
	}
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

func (m *memRepositories) PatchScanRunPhase(_ context.Context, id string, phase engine.ScanRunPhase, runErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.scans[id]
	if !ok {
		return storage.ErrNotFound
	}
	s.RunPhase = phase
	s.RunError = runErr
	s.UpdatedAt = time.Now().UTC()
	m.scans[id] = s
	return nil
}

func (m *memRepositories) SetScanStatusAndRunPhase(_ context.Context, id string, status engine.ScanStatus, phase engine.ScanRunPhase, runErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.scans[id]
	if !ok {
		return storage.ErrNotFound
	}
	s.Status = status
	s.RunPhase = phase
	s.RunError = runErr
	s.UpdatedAt = time.Now().UTC()
	m.scans[id] = s
	return nil
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
		if filter.RuleID != "" && f.RuleID != filter.RuleID {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func (m *memRepositories) ListFindingsPage(_ context.Context, scanID string, filter storage.FindingListFilter, opts storage.FindingListPageOptions) (storage.FindingListPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var list []findings.Finding
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
		if filter.RuleID != "" && f.RuleID != filter.RuleID {
			continue
		}
		list = append(list, f)
	}
	o := strings.TrimSpace(opts.SortOrder)
	if o == "" {
		o = storage.ListSortAsc
	}
	asc := strings.EqualFold(o, storage.ListSortAsc)
	sort.SliceStable(list, func(i, j int) bool {
		return storage.FindingLess(list[i], list[j], opts.SortField, asc)
	})
	start := 0
	if strings.TrimSpace(opts.Cursor) != "" {
		ts, id, pOrd, sevOrd, err := storage.DecodeListCursor(opts.Cursor, opts.SortField, o)
		if err != nil {
			return storage.FindingListPage{}, err
		}
		if pOrd != nil {
			return storage.FindingListPage{}, storage.ErrInvalidListCursor
		}
		found := false
		for i := range list {
			if storage.FindingKeysetAfter(list[i], ts, id, sevOrd, opts.SortField, asc) {
				start = i
				found = true
				break
			}
		}
		if !found {
			start = len(list)
		}
	}
	end := start + opts.Limit + 1
	if end > len(list) {
		end = len(list)
	}
	page := list[start:end]
	hasMore := len(page) > opts.Limit
	if hasMore {
		page = page[:opts.Limit]
	}
	out := storage.FindingListPage{Records: page, HasMore: hasMore}
	if hasMore && len(page) > 0 {
		cur, err := storage.EncodeFindingPageCursor(page[len(page)-1], opts.SortField, o)
		if err != nil {
			return storage.FindingListPage{}, err
		}
		out.NextCursor = cur
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
		ScanRun:     mem,
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
	var env ExecutionListResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Items == nil {
		t.Fatal("want non-nil items slice")
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

func TestScanRunStatus_findingsAndRuleFamilyCoverage(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/r/{id}"}}); rerr != nil {
		t.Fatal(rerr)
	}
	if uerr := mem.UpdateBaselineState(ctx, scan.ID, storage.BaselineState{Status: "succeeded", Total: 1, Done: 1}); uerr != nil {
		t.Fatal(uerr)
	}
	if uerr := mem.UpdateMutationState(ctx, scan.ID, storage.MutationState{Status: "succeeded", Total: 1, Done: 1}); uerr != nil {
		t.Fatal(uerr)
	}
	if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID:         scan.ID,
		ScanEndpointID: "ep1",
		Phase:          engine.PhaseMutated,
		RuleID:         "axiom.idor.path_swap.v1",
		RequestMethod:  "GET",
		RequestURL:     "http://example/r/1",
	}); ierr != nil {
		t.Fatal(ierr)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID:                 scan.ID,
		RuleID:                 "axiom.idor.path_swap.v1",
		Category:               "broken_object_level_authorization",
		Severity:               findings.SeverityHigh,
		RuleDeclaredConfidence: "high",
		AssessmentTier:         "confirmed",
		Summary:                "probe",
		ScanEndpointID:         "e1",
		BaselineExecutionID:    "b1",
		MutatedExecutionID:     "m1",
		Evidence:               storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	h := testHandler(mem)
	h.RulesDir = filepath.Join("..", "..", "rules", "builtin")
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var st ScanRunStatusResponse
	if derr := json.NewDecoder(resp.Body).Decode(&st); derr != nil {
		t.Fatal(derr)
	}
	if st.FindingsSummary.Total != 1 || st.FindingsSummary.BySeverity["high"] != 1 || st.FindingsSummary.ByAssessmentTier["confirmed"] != 1 {
		t.Fatalf("findings_summary %+v", st.FindingsSummary)
	}
	if st.Summary.FindingsCreated != 1 || st.Summary.EndpointsImported != 1 {
		t.Fatalf("summary %+v", st.Summary)
	}
	if !st.RuleFamilyCoverage.IDORPathOrQuery.Exercised || st.RuleFamilyCoverage.IDORPathOrQuery.MutatedExecutions != 1 {
		t.Fatalf("idor %+v", st.RuleFamilyCoverage.IDORPathOrQuery)
	}
	if st.RuleFamilyCoverage.UnavailableReason != nil {
		t.Fatalf("unexpected unavailable: %+v", st.RuleFamilyCoverage.UnavailableReason)
	}
}

func TestScanRunStatus_returnsProgress(t *testing.T) {
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

	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var st ScanRunStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Compatibility.ScanID != scan.ID || st.Run.Phase != string(engine.PhasePlanned) {
		t.Fatalf("%+v", st)
	}
	if st.Progress.EndpointsDiscovered != 0 {
		t.Fatalf("progress %+v", st.Progress)
	}
	if st.Coverage.AuthHeadersConfigured || st.Coverage.EndpointsDeclaringSecurity != 0 {
		t.Fatalf("coverage %+v", st.Coverage)
	}
	if st.Scan.ID != scan.ID || st.Run.Phase != st.Compatibility.Phase || st.Scan.Status != st.Compatibility.ScanStatus {
		t.Fatalf("compatibility must mirror canonical scan/run fields: %+v", st)
	}
	if len(st.Diagnostics.BlockedDetail) != 1 || st.Diagnostics.BlockedDetail[0].Code != "no_imported_endpoints" {
		t.Fatalf("diagnostics %+v", st.Diagnostics)
	}
	if st.Run.OrchestratorError != "" || st.Compatibility.LastError != "" {
		t.Fatalf("want empty orchestrator error, got run=%q compat=%q", st.Run.OrchestratorError, st.Compatibility.LastError)
	}
}

func TestScanRunStatus_progressReflectsPersistedTotals(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "lbl", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if uerr := mem.UpdateBaselineState(ctx, scan.ID, storage.BaselineState{Status: "succeeded", Error: "", Total: 3, Done: 3}); uerr != nil {
		t.Fatal(uerr)
	}
	if uerr := mem.UpdateMutationState(ctx, scan.ID, storage.MutationState{Status: "in_progress", Error: "", Total: 10, Done: 4}); uerr != nil {
		t.Fatal(uerr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st ScanRunStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Progress.BaselineEndpointsTotal != 3 || st.Progress.BaselineExecutionsCompleted != 3 {
		t.Fatalf("baseline totals %+v", st.Progress)
	}
	if st.Progress.MutationCandidatesTotal != 10 || st.Progress.MutationExecutionsCompleted != 4 {
		t.Fatalf("mutation totals %+v", st.Progress)
	}
	if st.Run.BaselineRunStatus != "succeeded" || st.Run.MutationRunStatus != "in_progress" {
		t.Fatalf("run state %+v", st.Run)
	}
	if len(st.Diagnostics.SkippedDetail) != 0 {
		t.Fatalf("unexpected skipped_detail: %+v", st.Diagnostics)
	}
}

func TestScanRunStatus_coverageHintsDeclaredSecurity(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{
		{Method: "GET", Path: "/r/{id}", SecuritySchemeHints: []string{"bearerAuth"}},
	}); rerr != nil {
		t.Fatal(rerr)
	}

	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var st ScanRunStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Coverage.EndpointsDeclaringSecurity != 1 || st.Coverage.AuthHeadersConfigured {
		t.Fatalf("%+v", st.Coverage)
	}
	if len(st.Coverage.Hints) != 1 || !strings.Contains(st.Coverage.Hints[0], "auth_headers") {
		t.Fatalf("%+v", st.Coverage.Hints)
	}
	found := false
	for _, b := range st.Diagnostics.BlockedDetail {
		if b.Code == "declared_security_without_auth" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want declared_security_without_auth in blocked_detail, got %+v", st.Diagnostics.BlockedDetail)
	}
}

func TestScanRunStatus_failureFieldSemantics(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if perr := mem.PatchScanRunPhase(ctx, scan.ID, engine.PhaseFailed, "orchestrator_stop"); perr != nil {
		t.Fatal(perr)
	}
	if perr := mem.UpdateBaselineState(ctx, scan.ID, storage.BaselineState{Status: "succeeded", Error: "stale_should_hide", Total: 1, Done: 1}); perr != nil {
		t.Fatal(perr)
	}
	if perr := mem.UpdateMutationState(ctx, scan.ID, storage.MutationState{Status: "failed", Error: "mutation_sub_fail", Total: 2, Done: 1}); perr != nil {
		t.Fatal(perr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st ScanRunStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Run.OrchestratorError != "orchestrator_stop" || st.Compatibility.LastError != "orchestrator_stop" {
		t.Fatalf("orchestrator error: run=%q compat=%q", st.Run.OrchestratorError, st.Compatibility.LastError)
	}
	if st.Run.BaselineRunError != "" {
		t.Fatalf("baseline error must be hidden when baseline status is not failed; got %q", st.Run.BaselineRunError)
	}
	if st.Run.MutationRunError != "mutation_sub_fail" {
		t.Fatalf("mutation sub error: %q", st.Run.MutationRunError)
	}
	if !st.Diagnostics.ResumeRecommended || st.Diagnostics.PhaseFailedNextStep == "" {
		t.Fatalf("want resume hint, got %+v", st.Diagnostics)
	}
}

func TestScanRunStatus_failureShowsBaselineSubErrorWhenFailed(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if perr := mem.PatchScanRunPhase(ctx, scan.ID, engine.PhaseFailed, "after_baseline"); perr != nil {
		t.Fatal(perr)
	}
	if perr := mem.UpdateBaselineState(ctx, scan.ID, storage.BaselineState{Status: "failed", Error: "no_imported_endpoints", Total: 0, Done: 0}); perr != nil {
		t.Fatal(perr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st ScanRunStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Run.BaselineRunError != "no_imported_endpoints" {
		t.Fatalf("want baseline sub-error: %+v", st.Run)
	}
	if st.Run.OrchestratorError != "after_baseline" {
		t.Fatalf("want orchestrator error: %+v", st.Run)
	}
}

func TestScanRunStatus_zeroMutationCandidatesSkippedDetail(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if perr := mem.UpdateBaselineState(ctx, scan.ID, storage.BaselineState{Status: "succeeded", Error: "", Total: 1, Done: 1}); perr != nil {
		t.Fatal(perr)
	}
	if perr := mem.UpdateMutationState(ctx, scan.ID, storage.MutationState{Status: "succeeded", Error: "", Total: 0, Done: 0}); perr != nil {
		t.Fatal(perr)
	}
	if perr := mem.PatchScanRunPhase(ctx, scan.ID, engine.PhaseFindingsComplete, ""); perr != nil {
		t.Fatal(perr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st ScanRunStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range st.Diagnostics.SkippedDetail {
		if s.Code == "zero_mutation_candidates" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want zero_mutation_candidates in %+v", st.Diagnostics.SkippedDetail)
	}
}

func TestScanRunStatus_postFailureReconcileStyleReadModel(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if perr := mem.UpdateBaselineState(ctx, scan.ID, storage.BaselineState{Status: "succeeded", Error: "", Total: 2, Done: 2}); perr != nil {
		t.Fatal(perr)
	}
	if perr := mem.PatchScanRunPhase(ctx, scan.ID, engine.PhaseBaselineComplete, ""); perr != nil {
		t.Fatal(perr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st ScanRunStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Run.Phase != string(engine.PhaseBaselineComplete) || st.Run.OrchestratorError != "" {
		t.Fatalf("want clean orchestrator fields after reconcile-style phase: %+v", st.Run)
	}
	if st.Diagnostics.ResumeRecommended {
		t.Fatalf("resume not expected when not failed: %+v", st.Diagnostics)
	}
}

func TestScanRunStatus_baselineNotRecordedSkippedWhenPlanned(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rperr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/x"}}); rperr != nil {
		t.Fatal(rperr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st ScanRunStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range st.Diagnostics.SkippedDetail {
		if s.Code == "baseline_not_recorded" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want baseline_not_recorded in %+v", st.Diagnostics)
	}
}

func TestScanRunControl_start_requiresOrchestrator(t *testing.T) {
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

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/scans/"+scan.ID+"/run", strings.NewReader(`{"action":"start"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestScanRunControl_cancelWithoutOrchestrator(t *testing.T) {
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

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/scans/"+scan.ID+"/run", strings.NewReader(`{"action":"cancel"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var st ScanRunStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Run.Phase != string(engine.PhaseCanceled) || st.Scan.Status != string(engine.ScanCanceled) {
		t.Fatalf("%+v", st)
	}
	if st.Run.Phase != st.Compatibility.Phase || st.Scan.ID != st.Compatibility.ScanID || st.Scan.Status != st.Compatibility.ScanStatus {
		t.Fatalf("compatibility must mirror canonical: %+v", st)
	}
}

func TestMemRepositories_duplicateFindingRejected(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	in := storage.CreateFindingInput{
		ScanID:                 scan.ID,
		RuleID:                 "r1",
		Category:               "c",
		Severity:               findings.Severity("high"),
		RuleDeclaredConfidence: "high",
		AssessmentTier:         "confirmed",
		Summary:                "s",
		ScanEndpointID:         "e1",
		BaselineExecutionID:    "b1",
		MutatedExecutionID:     "m1",
		Evidence:               storage.CreateEvidenceInput{},
	}
	if _, err := mem.CreateFinding(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := mem.CreateFinding(ctx, in); !errors.Is(err, storage.ErrDuplicateFinding) {
		t.Fatalf("got %v", err)
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
