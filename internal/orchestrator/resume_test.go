package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/executor/baseline"
	"github.com/codethor0/axiom-api-scanner/internal/executor/mutation"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

func TestBaselineSucceeded(t *testing.T) {
	if baselineSucceeded(engine.Scan{
		BaselineRunStatus:      "succeeded",
		BaselineEndpointsTotal: 2,
		BaselineEndpointsDone:  2,
	}) != true {
		t.Fatal("expected true")
	}
	if baselineSucceeded(engine.Scan{
		BaselineRunStatus:      "succeeded",
		BaselineEndpointsTotal: 2,
		BaselineEndpointsDone:  1,
	}) != false {
		t.Fatal("partial should be false")
	}
	if baselineSucceeded(engine.Scan{
		BaselineRunStatus:      "failed",
		BaselineEndpointsTotal: 1,
		BaselineEndpointsDone:  1,
	}) != false {
		t.Fatal("non-succeeded status")
	}
}

type countingBaseline struct {
	calls int
}

func (c *countingBaseline) RunWithOptions(ctx context.Context, scanID string, opts baseline.RunOptions) (baseline.Result, error) {
	c.calls++
	return baseline.Result{Status: "succeeded", EndpointsTotal: 1, EndpointsExecuted: 1}, nil
}

// stubResumeStore is a minimal RunStore + mutation.Store for resume-without-baseline tests.
type stubResumeStore struct {
	scan      engine.Scan
	endpoints []engine.ScanEndpoint
}

func (s *stubResumeStore) CreateScan(context.Context, storage.CreateScanInput) (engine.Scan, error) {
	panic("CreateScan")
}
func (s *stubResumeStore) GetScan(_ context.Context, id string) (engine.Scan, error) {
	if s.scan.ID != id {
		return engine.Scan{}, storage.ErrNotFound
	}
	return s.scan, nil
}
func (s *stubResumeStore) ApplyControl(context.Context, string, storage.ScanControlAction) (engine.Scan, error) {
	panic("ApplyControl")
}
func (s *stubResumeStore) PatchScanRunPhase(_ context.Context, id string, phase engine.ScanRunPhase, runErr string) error {
	if s.scan.ID != id {
		return storage.ErrNotFound
	}
	s.scan.RunPhase = phase
	s.scan.RunError = runErr
	return nil
}
func (s *stubResumeStore) SetScanStatusAndRunPhase(_ context.Context, id string, status engine.ScanStatus, phase engine.ScanRunPhase, runErr string) error {
	if s.scan.ID != id {
		return storage.ErrNotFound
	}
	s.scan.Status = status
	s.scan.RunPhase = phase
	s.scan.RunError = runErr
	return nil
}
func (s *stubResumeStore) PatchScanTarget(context.Context, string, storage.PatchScanTargetInput) (engine.Scan, error) {
	panic("PatchScanTarget")
}
func (s *stubResumeStore) ReplaceScanEndpoints(context.Context, string, []engine.EndpointSpec) error {
	panic("ReplaceScanEndpoints")
}
func (s *stubResumeStore) ListScanEndpoints(_ context.Context, scanID string, _ storage.EndpointListFilter) ([]engine.ScanEndpoint, error) {
	if s.scan.ID != scanID {
		return nil, storage.ErrNotFound
	}
	return s.endpoints, nil
}
func (s *stubResumeStore) ListScanEndpointsForRunStatus(ctx context.Context, scanID string, filter storage.EndpointListFilter) ([]engine.ScanEndpoint, error) {
	return s.ListScanEndpoints(ctx, scanID, filter)
}
func (s *stubResumeStore) ListEndpointInventoryPage(ctx context.Context, scanID string, filter storage.EndpointListFilter, _ storage.EndpointInventoryOptions, page storage.EndpointListPageOptions) (storage.EndpointListPage, error) {
	if page.Limit <= 0 {
		return storage.EndpointListPage{}, fmt.Errorf("invalid limit")
	}
	eps, err := s.ListScanEndpoints(ctx, scanID, filter)
	if err != nil {
		return storage.EndpointListPage{}, err
	}
	out := make([]storage.EndpointInventoryEntry, len(eps))
	for i, ep := range eps {
		out[i] = storage.EndpointInventoryEntry{Endpoint: ep}
	}
	o := strings.TrimSpace(page.SortOrder)
	if o == "" {
		o = storage.ListSortAsc
	}
	sf := strings.TrimSpace(page.SortField)
	if sf == "" {
		sf = storage.EndpointListSortPath
	}
	asc := strings.EqualFold(o, storage.ListSortAsc)
	sort.SliceStable(out, func(i, j int) bool {
		return storage.EndpointLess(out[i].Endpoint, out[j].Endpoint, sf, asc)
	})
	start := 0
	if strings.TrimSpace(page.Cursor) != "" {
		path, method, id, ca, derr := storage.DecodeEndpointCursor(page.Cursor, sf, o)
		if derr != nil {
			return storage.EndpointListPage{}, derr
		}
		found := false
		for i := range out {
			if storage.EndpointKeysetAfter(out[i].Endpoint, path, method, id, ca, sf, asc) {
				start = i
				found = true
				break
			}
		}
		if !found {
			start = len(out)
		}
	}
	end := start + page.Limit + 1
	if end > len(out) {
		end = len(out)
	}
	recs := out[start:end]
	hasMore := len(recs) > page.Limit
	if hasMore {
		recs = recs[:page.Limit]
	}
	p := storage.EndpointListPage{Records: recs, HasMore: hasMore}
	if hasMore && len(recs) > 0 {
		cur, cerr := storage.EncodeEndpointPageCursor(sf, o, recs[len(recs)-1])
		if cerr != nil {
			return storage.EndpointListPage{}, cerr
		}
		p.NextCursor = cur
	}
	return p, nil
}
func (s *stubResumeStore) UpdateBaselineState(_ context.Context, scanID string, st storage.BaselineState) error {
	if s.scan.ID != scanID {
		return storage.ErrNotFound
	}
	s.scan.BaselineRunStatus = st.Status
	s.scan.BaselineRunError = st.Error
	s.scan.BaselineEndpointsTotal = st.Total
	s.scan.BaselineEndpointsDone = st.Done
	return nil
}
func (s *stubResumeStore) InsertExecutionRecord(context.Context, engine.ExecutionRecord) (string, error) {
	panic("InsertExecutionRecord")
}
func (s *stubResumeStore) GetLatestExecution(context.Context, string, string, engine.ExecutionPhase) (engine.ExecutionRecord, error) {
	return engine.ExecutionRecord{}, storage.ErrNotFound
}
func (s *stubResumeStore) GetMutationByCandidate(context.Context, string, string, string, string) (engine.ExecutionRecord, error) {
	return engine.ExecutionRecord{}, storage.ErrNotFound
}
func (s *stubResumeStore) UpdateMutationState(_ context.Context, scanID string, st storage.MutationState) error {
	if s.scan.ID != scanID {
		return storage.ErrNotFound
	}
	s.scan.MutationRunStatus = st.Status
	s.scan.MutationRunError = st.Error
	s.scan.MutationCandidatesTotal = st.Total
	s.scan.MutationCandidatesDone = st.Done
	return nil
}
func (s *stubResumeStore) GetByEvidenceTuple(context.Context, string, string, string, string, string) (findings.Finding, error) {
	return findings.Finding{}, storage.ErrNotFound
}
func (s *stubResumeStore) CreateFinding(context.Context, storage.CreateFindingInput) (findings.Finding, error) {
	panic("CreateFinding")
}

func TestService_Run_resumeSkipsBaselineWhenAlreadySucceeded(t *testing.T) {
	id := "550e8400-e29b-41d4-a716-446655440000"
	st := &stubResumeStore{
		scan: engine.Scan{
			ID:                     id,
			Status:                 engine.ScanRunning,
			RunPhase:               engine.PhaseFailed,
			RunError:               "mutation_failed",
			BaseURL:                "http://127.0.0.1:9",
			BaselineRunStatus:      "succeeded",
			BaselineEndpointsTotal: 1,
			BaselineEndpointsDone:  1,
			MutationRunStatus:      "failed",
			MutationRunError:       "prior_error",
		},
		endpoints: nil,
	}
	cb := &countingBaseline{}
	svc := &Service{
		Store:     st,
		Baseline:  cb,
		Mutations: mutation.NewRunner(st),
		LoadRules: func() ([]rules.Rule, error) { return nil, nil },
	}
	if err := svc.Run(context.Background(), id, Options{ResumeRetry: true}); err != nil {
		t.Fatal(err)
	}
	if cb.calls != 0 {
		t.Fatalf("baseline should be skipped on resume when already succeeded; calls=%d", cb.calls)
	}
	if st.scan.RunPhase != engine.PhaseFindingsComplete || st.scan.Status != engine.ScanCompleted {
		t.Fatalf("want completed + findings_complete, got phase=%s status=%s", st.scan.RunPhase, st.scan.Status)
	}
}

// baselineAfterStub wraps counting baseline and updates scan row like a successful baseline pass (test-only).
type baselineAfterStub struct {
	inner *countingBaseline
	st    *stubResumeStore
}

func (b *baselineAfterStub) RunWithOptions(ctx context.Context, scanID string, opts baseline.RunOptions) (baseline.Result, error) {
	res, err := b.inner.RunWithOptions(ctx, scanID, opts)
	if err != nil {
		return res, err
	}
	if err := b.st.UpdateBaselineState(ctx, scanID, storage.BaselineState{
		Status: "succeeded", Error: "", Total: 1, Done: 1,
	}); err != nil {
		return baseline.Result{}, err
	}
	return res, nil
}

func TestService_Run_startInvokesBaselineOnceWhenNotYetSucceeded(t *testing.T) {
	id := "550e8400-e29b-41d4-a716-446655440000"
	st := &stubResumeStore{
		scan: engine.Scan{
			ID:                     id,
			Status:                 engine.ScanRunning,
			RunPhase:               engine.PhasePlanned,
			BaseURL:                "http://127.0.0.1:9",
			BaselineRunStatus:      "",
			BaselineEndpointsTotal: 0,
			BaselineEndpointsDone:  0,
		},
		endpoints: nil,
	}
	cb := &countingBaseline{}
	svc := &Service{
		Store: st,
		Baseline: &baselineAfterStub{
			inner: cb,
			st:    st,
		},
		Mutations: mutation.NewRunner(st),
		LoadRules: func() ([]rules.Rule, error) { return nil, nil },
	}
	if err := svc.Run(context.Background(), id, Options{ResumeRetry: false}); err != nil {
		t.Fatal(err)
	}
	if cb.calls != 1 {
		t.Fatalf("expected baseline invoked once; calls=%d", cb.calls)
	}
}
