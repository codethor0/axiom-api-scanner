package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

func TestDeriveRunProgressionSource_orchestratorWhenPhaseMoved(t *testing.T) {
	s := engine.Scan{RunPhase: engine.PhaseFindingsComplete}
	if g := DeriveRunProgressionSource(s); g != RunProgressionOrchestrator {
		t.Fatal(g)
	}
}

func TestDeriveRunProgressionSource_adhocWhenPlannedWithRunnerSignals(t *testing.T) {
	cases := []engine.Scan{
		{RunPhase: engine.PhasePlanned, BaselineRunStatus: "succeeded"},
		{RunPhase: engine.PhasePlanned, MutationRunStatus: "succeeded"},
		{RunPhase: engine.PhasePlanned, FindingsCount: 3},
	}
	for _, s := range cases {
		if g := DeriveRunProgressionSource(s); g != RunProgressionAdhoc {
			t.Fatalf("%+v got %q", s, g)
		}
	}
}

func TestDeriveRunProgressionSource_idle(t *testing.T) {
	s := engine.Scan{RunPhase: engine.PhasePlanned}
	if g := DeriveRunProgressionSource(s); g != RunProgressionIdle {
		t.Fatal(g)
	}
}

func TestDeriveFindingsRecordingStatus(t *testing.T) {
	if g := DeriveFindingsRecordingStatus(engine.Scan{MutationRunStatus: "succeeded"}); g != FindingsRecordingComplete {
		t.Fatal(g)
	}
	if g := DeriveFindingsRecordingStatus(engine.Scan{MutationRunStatus: "failed"}); g != FindingsRecordingMutationFailed {
		t.Fatal(g)
	}
	if g := DeriveFindingsRecordingStatus(engine.Scan{MutationRunStatus: "in_progress"}); g != FindingsRecordingMutationInProgress {
		t.Fatal(g)
	}
	if g := DeriveFindingsRecordingStatus(engine.Scan{}); g != FindingsRecordingMutationNotRun {
		t.Fatal(g)
	}
}

func TestContract_scanRunStatus_progressionSemantics_adHocVsOrchestrator(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := mem.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{{Method: "GET", Path: "/x"}}); rerr != nil {
		t.Fatal(rerr)
	}
	h := testHandler(mem)
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	body, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if rerr != nil {
		t.Fatal(rerr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	assertScanRunStatusWireShape(t, body)
	var env ScanRunStatusResponse
	if uerr := json.Unmarshal(body, &env); uerr != nil {
		t.Fatal(uerr)
	}
	if env.Run.ProgressionSource != RunProgressionIdle || env.Run.FindingsRecordingStatus != FindingsRecordingMutationNotRun {
		t.Fatalf("idle scan: %+v", env.Run)
	}

	mem.mu.Lock()
	s := mem.scans[scan.ID]
	s.BaselineRunStatus = "succeeded"
	s.BaselineEndpointsTotal = 1
	s.BaselineEndpointsDone = 1
	s.MutationRunStatus = "succeeded"
	s.MutationCandidatesTotal = 1
	s.MutationCandidatesDone = 1
	s.RunPhase = engine.PhasePlanned
	mem.scans[scan.ID] = s
	mem.mu.Unlock()

	resp2, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp2.StatusCode)
	}
	var env2 ScanRunStatusResponse
	if uerr := json.Unmarshal(body2, &env2); uerr != nil {
		t.Fatal(uerr)
	}
	if env2.Run.ProgressionSource != RunProgressionAdhoc {
		t.Fatalf("adhoc: %+v", env2.Run)
	}
	if env2.Run.FindingsRecordingStatus != FindingsRecordingComplete {
		t.Fatal(env2.Run.FindingsRecordingStatus)
	}
	if env2.Run.Phase != string(engine.PhasePlanned) {
		t.Fatal(env2.Run.Phase)
	}

	mem.mu.Lock()
	s = mem.scans[scan.ID]
	s.RunPhase = engine.PhaseFindingsComplete
	mem.scans[scan.ID] = s
	mem.mu.Unlock()

	resp3, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/run/status")
	if err != nil {
		t.Fatal(err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp3.StatusCode)
	}
	var env3 ScanRunStatusResponse
	if uerr := json.Unmarshal(body3, &env3); uerr != nil {
		t.Fatal(uerr)
	}
	if env3.Run.ProgressionSource != RunProgressionOrchestrator {
		t.Fatalf("orchestrator: %+v", env3.Run)
	}
	if env3.Run.Phase != string(engine.PhaseFindingsComplete) {
		t.Fatal(env3.Run.Phase)
	}
}
