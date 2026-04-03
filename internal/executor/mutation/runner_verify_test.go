package mutation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/google/uuid"
)

type memMutationStore struct {
	mu           sync.Mutex
	scan         engine.Scan
	endpoint     engine.ScanEndpoint
	baseline     engine.ExecutionRecord
	execs        map[string]engine.ExecutionRecord
	createCalls  int
	lastFinding  findings.Finding
}

func (m *memMutationStore) GetScan(_ context.Context, id string) (engine.Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scan.ID != id {
		return engine.Scan{}, storage.ErrNotFound
	}
	return m.scan, nil
}

func (m *memMutationStore) ListScanEndpoints(_ context.Context, scanID string) ([]engine.ScanEndpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scan.ID != scanID {
		return nil, storage.ErrNotFound
	}
	return []engine.ScanEndpoint{m.endpoint}, nil
}

func (m *memMutationStore) GetLatestExecution(_ context.Context, scanID, scanEndpointID string, phase engine.ExecutionPhase) (engine.ExecutionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.baseline.ScanID != scanID || m.baseline.ScanEndpointID != scanEndpointID || m.baseline.Phase != phase {
		return engine.ExecutionRecord{}, storage.ErrNotFound
	}
	return m.baseline, nil
}

func (m *memMutationStore) InsertExecutionRecord(_ context.Context, rec engine.ExecutionRecord) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.NewString()
	rec.ID = id
	rec.CreatedAt = time.Now().UTC()
	if m.execs == nil {
		m.execs = make(map[string]engine.ExecutionRecord)
	}
	m.execs[id] = rec
	return id, nil
}

func (m *memMutationStore) UpdateMutationState(_ context.Context, scanID string, st storage.MutationState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scan.ID != scanID {
		return storage.ErrNotFound
	}
	m.scan.MutationRunStatus = st.Status
	m.scan.MutationRunError = st.Error
	m.scan.MutationCandidatesTotal = st.Total
	m.scan.MutationCandidatesDone = st.Done
	return nil
}

func (m *memMutationStore) CreateFinding(_ context.Context, in storage.CreateFindingInput) (findings.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalls++
	id := uuid.NewString()
	f := findings.Finding{
		ID:                   id,
		ScanID:               in.ScanID,
		RuleID:               in.RuleID,
		Category:             in.Category,
		Severity:             in.Severity,
		Confidence:           in.Confidence,
		Summary:              in.Summary,
		EvidenceSummary:      in.EvidenceSummary,
		ScanEndpointID:       in.ScanEndpointID,
		BaselineExecutionID:  in.BaselineExecutionID,
		MutatedExecutionID:   in.MutatedExecutionID,
		Status:               in.FindingStatus,
		CreatedAt:            time.Now().UTC(),
	}
	if in.EvidenceURI == "" {
		f.EvidenceURI = "/v1/findings/" + id + "/evidence"
	} else {
		f.EvidenceURI = in.EvidenceURI
	}
	m.lastFinding = f
	return f, nil
}

func TestRunner_doesNotCreateFindingWhenDiffIncomplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"k": "v"})
	}))
	t.Cleanup(srv.Close)

	scanID := uuid.NewString()
	epID := uuid.NewString()
	st := &memMutationStore{
		scan: engine.Scan{
			ID:                   scanID,
			BaseURL:              srv.URL,
			BaselineRunStatus:    "succeeded",
			AuthHeaders:          map[string]string{},
			MutationRunStatus:    "",
			MutationCandidatesTotal: 0,
		},
		endpoint: engine.ScanEndpoint{
			ID:           epID,
			ScanID:       scanID,
			Method:       "GET",
			PathTemplate: "/items/{id}",
		},
		baseline: engine.ExecutionRecord{
			ID:                  "base-1",
			ScanID:              scanID,
			ScanEndpointID:      epID,
			Phase:               engine.PhaseBaseline,
			RequestMethod:       "GET",
			RequestURL:          srv.URL + "/items/axiom-id-ph",
			ResponseStatus:      200,
			ResponseBody:        `{"k":"v"}`,
			ResponseContentType: "application/json",
			CreatedAt:           time.Now().UTC(),
		},
	}

	ru := rules.Rule{
		ID:         "rule.badmatcher",
		Category:   "test",
		Severity:   "low",
		Confidence: "low",
		Target:     rules.RuleTarget{Methods: []string{"GET"}, Where: "path_params"},
		Mutations: []rules.Mutation{
			{Kind: rules.MutationReplacePathParam, ReplacePathParam: &rules.ReplacePathParamMutation{
				Param: "id", From: "a", To: "b",
			}},
		},
		Matchers: []rules.Matcher{
			{Kind: rules.MatcherKind("unknown_kind_for_test")},
		},
	}

	work, err := BuildWorkList([]engine.ScanEndpoint{st.endpoint}, []rules.Rule{ru})
	if err != nil {
		t.Fatal(err)
	}
	if len(work) != 1 {
		t.Fatalf("work %d", len(work))
	}

	r := NewRunner(st)
	r.HTTP = srv.Client()
	res, err := r.Run(context.Background(), scanID, work)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "succeeded" {
		t.Fatalf("%+v", res)
	}
	if st.createCalls != 0 {
		t.Fatalf("CreateFinding called %d times, want 0", st.createCalls)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "diff_incomplete") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("warnings %+v", res.Warnings)
	}
}

func TestRunner_createsFindingWhenMatchersPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"k": "v"})
	}))
	t.Cleanup(srv.Close)

	scanID := uuid.NewString()
	epID := uuid.NewString()
	st := &memMutationStore{
		scan: engine.Scan{
			ID:                scanID,
			BaseURL:           srv.URL,
			BaselineRunStatus: "succeeded",
			AuthHeaders:       map[string]string{},
		},
		endpoint: engine.ScanEndpoint{
			ID:           epID,
			ScanID:       scanID,
			Method:       "GET",
			PathTemplate: "/items/{id}",
		},
		baseline: engine.ExecutionRecord{
			ID:                  "base-1",
			ScanID:              scanID,
			ScanEndpointID:      epID,
			Phase:               engine.PhaseBaseline,
			RequestMethod:       "GET",
			RequestURL:          srv.URL + "/items/axiom-id-ph",
			ResponseStatus:      200,
			ResponseBody:        `{"k":"v"}`,
			ResponseContentType: "application/json",
			CreatedAt:           time.Now().UTC(),
		},
	}

	ru := rules.Rule{
		ID:         "rule.ok",
		Category:   "test",
		Severity:   "high",
		Confidence: "high",
		Target:     rules.RuleTarget{Methods: []string{"GET"}, Where: "path_params"},
		Mutations: []rules.Mutation{
			{Kind: rules.MutationReplacePathParam, ReplacePathParam: &rules.ReplacePathParamMutation{
				Param: "id", From: "a", To: "b",
			}},
		},
		Matchers: []rules.Matcher{
			{Kind: rules.MatcherStatusCodeUnchanged},
			{Kind: rules.MatcherResponseBodySimilarity, ResponseBodySimilarity: &rules.ResponseBodySimilarityMatcher{MinScore: 0.95}},
		},
	}

	work, err := BuildWorkList([]engine.ScanEndpoint{st.endpoint}, []rules.Rule{ru})
	if err != nil || len(work) != 1 {
		t.Fatal(work, err)
	}

	r := NewRunner(st)
	r.HTTP = srv.Client()
	res, err := r.Run(context.Background(), scanID, work)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.FindingIDs) != 1 || st.createCalls != 1 {
		t.Fatalf("findings %+v calls %d", res.FindingIDs, st.createCalls)
	}
	if st.lastFinding.BaselineExecutionID != "base-1" {
		t.Fatal(st.lastFinding)
	}
	if st.lastFinding.Confidence != "confirmed" || st.lastFinding.Status != "confirmed" {
		t.Fatalf("want confirmed tier got conf=%q status=%q", st.lastFinding.Confidence, st.lastFinding.Status)
	}
	if len(st.lastFinding.EvidenceSummary) == 0 {
		t.Fatal("expected evidence_summary json")
	}
}

