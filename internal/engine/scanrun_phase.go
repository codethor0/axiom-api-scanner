package engine

import (
	"errors"
	"fmt"
	"strings"
)

// ScanRunPhase is the persisted orchestration step for a V1 scan.
type ScanRunPhase string

const (
	PhasePlanned            ScanRunPhase = "planned"
	PhaseBaselineRunning    ScanRunPhase = "baseline_running"
	PhaseBaselineComplete   ScanRunPhase = "baseline_complete"
	PhaseMutationRunning    ScanRunPhase = "mutation_running"
	PhaseMutationComplete   ScanRunPhase = "mutation_complete"
	PhaseFindingsComplete   ScanRunPhase = "findings_complete"
	PhaseFailed             ScanRunPhase = "failed"
	PhaseCanceled           ScanRunPhase = "canceled"
)

// AllScanRunPhases lists every defined phase for tests and validation.
var AllScanRunPhases = []ScanRunPhase{
	PhasePlanned,
	PhaseBaselineRunning,
	PhaseBaselineComplete,
	PhaseMutationRunning,
	PhaseMutationComplete,
	PhaseFindingsComplete,
	PhaseFailed,
	PhaseCanceled,
}

// IsTerminal reports whether no forward orchestration step applies without operator action.
func IsTerminal(p ScanRunPhase) bool {
	switch p {
	case PhaseFindingsComplete, PhaseFailed, PhaseCanceled:
		return true
	default:
		return false
	}
}

// ValidateScanRunTransition enforces the directed graph of phase moves.
// resumeRetry allows leaving PhaseFailed to retry forward execution.
func ValidateScanRunTransition(from, to ScanRunPhase, resumeRetry bool) error {
	if from == to {
		return nil
	}
	if IsTerminal(from) && from != PhaseFailed {
		return fmt.Errorf("%w: cannot transition from terminal phase %q", ErrInvalidScanRunPhase, from)
	}
	if from == PhaseFailed && !resumeRetry {
		return fmt.Errorf("%w: cannot transition from failed without explicit resume retry", ErrInvalidScanRunPhase)
	}
	allowed := forwardTransitions(from, resumeRetry)
	for _, a := range allowed {
		if a == to {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot transition from %q to %q", ErrInvalidScanRunPhase, from, to)
}

func forwardTransitions(from ScanRunPhase, resumeRetry bool) []ScanRunPhase {
	switch from {
	case PhasePlanned:
		return []ScanRunPhase{PhaseBaselineRunning, PhaseCanceled, PhaseFailed}
	case PhaseBaselineRunning:
		return []ScanRunPhase{PhaseBaselineComplete, PhaseFailed, PhaseCanceled}
	case PhaseBaselineComplete:
		return []ScanRunPhase{PhaseMutationRunning, PhaseFailed, PhaseCanceled}
	case PhaseMutationRunning:
		return []ScanRunPhase{PhaseMutationComplete, PhaseFailed, PhaseCanceled}
	case PhaseMutationComplete:
		return []ScanRunPhase{PhaseFindingsComplete, PhaseFailed, PhaseCanceled}
	case PhaseFindingsComplete:
		return nil
	case PhaseFailed:
		if resumeRetry {
			// Orchestrator chooses next concrete phase from persisted execution state.
			return []ScanRunPhase{PhaseBaselineRunning, PhaseBaselineComplete, PhaseMutationRunning}
		}
		return nil
	case PhaseCanceled:
		return nil
	default:
		return nil
	}
}

// ParseScanRunPhase normalizes user/API input.
func ParseScanRunPhase(s string) (ScanRunPhase, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	for _, p := range AllScanRunPhases {
		if string(p) == s {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w: unknown scan run phase %q", ErrInvalidScanRunPhase, s)
}

// ErrInvalidScanRunPhase indicates an illegal or unknown run phase or transition.
var ErrInvalidScanRunPhase = errors.New("invalid scan run phase")
