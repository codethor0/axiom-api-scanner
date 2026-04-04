package engine

import (
	"errors"
	"testing"
)

func TestParseScanRunPhase(t *testing.T) {
	p, err := ParseScanRunPhase("  BASELINE_COMPLETE ")
	if err != nil {
		t.Fatal(err)
	}
	if p != PhaseBaselineComplete {
		t.Fatalf("got %q", p)
	}
	if _, err := ParseScanRunPhase("nope"); err == nil {
		t.Fatal("want error")
	}
}

func TestValidateScanRunTransition_forwardChain(t *testing.T) {
	chain := []ScanRunPhase{
		PhasePlanned, PhaseBaselineRunning, PhaseBaselineComplete,
		PhaseMutationRunning, PhaseMutationComplete, PhaseFindingsComplete,
	}
	for i := 0; i < len(chain)-1; i++ {
		if err := ValidateScanRunTransition(chain[i], chain[i+1], false, false); err != nil {
			t.Fatalf("%q -> %q: %v", chain[i], chain[i+1], err)
		}
	}
}

func TestValidateScanRunTransition_illegal(t *testing.T) {
	errJump := ValidateScanRunTransition(PhasePlanned, PhaseMutationRunning, false, false)
	if errJump == nil {
		t.Fatal("want error for planned -> mutation_running")
	}
	errTerm := ValidateScanRunTransition(PhaseFindingsComplete, PhasePlanned, false, false)
	if errTerm == nil {
		t.Fatal("want error from terminal findings_complete")
	}
}

func TestValidateScanRunTransition_fromFailedResume(t *testing.T) {
	if err := ValidateScanRunTransition(PhaseFailed, PhaseMutationRunning, true, false); err != nil {
		t.Fatal(err)
	}
	if err := ValidateScanRunTransition(PhaseFailed, PhaseBaselineComplete, true, false); err != nil {
		t.Fatal(err)
	}
	if err := ValidateScanRunTransition(PhaseFailed, PhaseMutationRunning, false, false); err == nil {
		t.Fatal("want error without resume flag")
	}
}

func TestValidateScanRunTransition_forceRerunBaselineFromComplete(t *testing.T) {
	if err := ValidateScanRunTransition(PhaseBaselineComplete, PhaseBaselineRunning, false, false); err == nil {
		t.Fatal("want error without force flag")
	}
	if err := ValidateScanRunTransition(PhaseBaselineComplete, PhaseBaselineRunning, false, true); err != nil {
		t.Fatal(err)
	}
}

func TestValidateScanRunTransition_canceledIsTerminal(t *testing.T) {
	if err := ValidateScanRunTransition(PhaseCanceled, PhasePlanned, true, false); err == nil {
		t.Fatal("want error from canceled")
	}
}

func TestValidateScanRunTransition_samePhase(t *testing.T) {
	if err := ValidateScanRunTransition(PhasePlanned, PhasePlanned, false, false); err != nil {
		t.Fatal(err)
	}
}

func TestIsTerminal(t *testing.T) {
	if !IsTerminal(PhaseFindingsComplete) || !IsTerminal(PhaseFailed) || !IsTerminal(PhaseCanceled) {
		t.Fatal("expected terminal")
	}
	if IsTerminal(PhasePlanned) {
		t.Fatal("planned not terminal")
	}
}

func TestErrInvalidScanRunPhase_type(t *testing.T) {
	err := ValidateScanRunTransition(PhasePlanned, PhaseMutationRunning, false, false)
	if err == nil {
		t.Fatal("want error")
	}
	if !errors.Is(err, ErrInvalidScanRunPhase) {
		t.Fatalf("want ErrInvalidScanRunPhase wrapper: %v", err)
	}
}
