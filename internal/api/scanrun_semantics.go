package api

import (
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

// Progression source: who advanced persisted execution relative to orchestration (run_phase).
const (
	RunProgressionOrchestrator = "orchestrator"
	RunProgressionAdhoc        = "adhoc"
	RunProgressionIdle         = "idle"
)

// Findings recording status from persisted mutation runner only (findings_count may be zero when complete).
const (
	FindingsRecordingMutationNotRun     = "mutation_not_run"
	FindingsRecordingMutationInProgress = "mutation_in_progress"
	FindingsRecordingMutationFailed     = "mutation_failed"
	FindingsRecordingComplete           = "complete"
)

// DeriveRunProgressionSource reports whether persisted run_phase has left "planned" (orchestrator/cancel path)
// or execution was driven only by ad-hoc POST .../executions/baseline|mutations (phase stays planned).
func DeriveRunProgressionSource(scan engine.Scan) string {
	if scan.RunPhase != engine.PhasePlanned {
		return RunProgressionOrchestrator
	}
	bs := strings.TrimSpace(scan.BaselineRunStatus)
	ms := strings.TrimSpace(scan.MutationRunStatus)
	if bs != "" || ms != "" || scan.FindingsCount > 0 {
		return RunProgressionAdhoc
	}
	return RunProgressionIdle
}

// DeriveFindingsRecordingStatus summarizes the mutation pass outcome for the finding pipeline (persisted scan columns only).
func DeriveFindingsRecordingStatus(scan engine.Scan) string {
	switch strings.TrimSpace(scan.MutationRunStatus) {
	case "succeeded":
		return FindingsRecordingComplete
	case "failed":
		return FindingsRecordingMutationFailed
	case "in_progress":
		return FindingsRecordingMutationInProgress
	default:
		return FindingsRecordingMutationNotRun
	}
}
