package orchestrator

import (
	"context"
	"errors"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/executor/baseline"
	"github.com/codethor0/axiom-api-scanner/internal/executor/mutation"
	"github.com/codethor0/axiom-api-scanner/internal/rules"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

// BaselineRunner runs or skips baseline HTTP work for orchestration.
type BaselineRunner interface {
	RunWithOptions(ctx context.Context, scanID string, opts baseline.RunOptions) (baseline.Result, error)
}

// RunStore is the persistence surface required for scan orchestration.
type RunStore interface {
	storage.ScanRepository
	storage.ScanRunRepository
	storage.ScanTargetRepository
	storage.EndpointRepository
}

// Service sequences baseline, rule planning, mutation, and finding persistence for V1 scans.
type Service struct {
	Store     RunStore
	Baseline  BaselineRunner
	Mutations *mutation.Runner
	LoadRules func() ([]rules.Rule, error)
}

// Options tune orchestration (resume, optional baseline rerun).
type Options struct {
	ResumeRetry        bool
	ForceRerunBaseline bool
}

// Run executes or resumes the canonical V1 scan pipeline until completion, failure, or cancel.
func (s *Service) Run(ctx context.Context, scanID string, opts Options) error {
	if s == nil || s.Store == nil || s.Baseline == nil || s.Mutations == nil {
		return errors.New("orchestrator: incomplete dependencies")
	}
	if strings.TrimSpace(scanID) == "" {
		return errors.New("orchestrator: scan id required")
	}

	fail := func(msg string) error {
		_ = s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanFailed, engine.PhaseFailed, msg)
		return errors.New(msg)
	}

	scan, err := s.Store.GetScan(ctx, scanID)
	if err != nil {
		return err
	}
	if scan.Status == engine.ScanQueued {
		if _, aerr := s.Store.ApplyControl(ctx, scanID, storage.ScanControlStart); aerr != nil && !errors.Is(aerr, storage.ErrInvalidTransition) {
			return aerr
		}
		scan, err = s.Store.GetScan(ctx, scanID)
		if err != nil {
			return err
		}
	}

	// Completed / canceled runs are idempotent at the API: second start/resume should not fail.
	if scan.Status == engine.ScanCompleted && scan.RunPhase == engine.PhaseFindingsComplete {
		return nil
	}
	if scan.Status == engine.ScanCanceled || scan.RunPhase == engine.PhaseCanceled {
		return nil
	}

	if recErr := s.reconcileRunPhaseForResume(ctx, scanID, &scan, opts); recErr != nil {
		return recErr
	}

	needBaseline := opts.ForceRerunBaseline || !baselineSucceeded(scan)
	if needBaseline {
		if advErr := s.advancePhase(ctx, scanID, engine.PhaseBaselineRunning, opts); advErr != nil {
			return advErr
		}
		if canceled, canErr := scanCanceled(ctx, s.Store, scanID); canErr != nil {
			return canErr
		} else if canceled {
			return s.finishCancel(ctx, scanID)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			_ = s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanFailed, engine.PhaseFailed, ctxErr.Error())
			return ctxErr
		}

		bOpts := baseline.RunOptions{Force: opts.ForceRerunBaseline}
		if _, baseErr := s.Baseline.RunWithOptions(ctx, scanID, bOpts); baseErr != nil {
			_ = s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanFailed, engine.PhaseFailed, baseErr.Error())
			return baseErr
		}

		scan, err = s.Store.GetScan(ctx, scanID)
		if err != nil {
			return err
		}
		if scan.BaselineRunStatus != "succeeded" {
			msg := strings.TrimSpace(scan.BaselineRunError)
			if msg == "" {
				msg = "baseline_did_not_succeed"
			}
			return fail(msg)
		}
	} else {
		// Baseline already succeeded and not forcing rerun: stay honest in phase without re-entering baseline_running.
		if advErr := s.advancePhase(ctx, scanID, engine.PhaseBaselineComplete, opts); advErr != nil {
			return advErr
		}
		scan, err = s.Store.GetScan(ctx, scanID)
		if err != nil {
			return err
		}
	}

	if canceled, canMid := scanCanceled(ctx, s.Store, scanID); canMid != nil {
		return canMid
	} else if canceled {
		return s.finishCancel(ctx, scanID)
	}

	if errBC := s.advancePhase(ctx, scanID, engine.PhaseBaselineComplete, opts); errBC != nil {
		return errBC
	}
	if errMR := s.advancePhase(ctx, scanID, engine.PhaseMutationRunning, opts); errMR != nil {
		return errMR
	}
	if canceled, canErr2 := scanCanceled(ctx, s.Store, scanID); canErr2 != nil {
		return canErr2
	} else if canceled {
		return s.finishCancel(ctx, scanID)
	}
	if ctxErr2 := ctx.Err(); ctxErr2 != nil {
		_ = s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanFailed, engine.PhaseFailed, ctxErr2.Error())
		return ctxErr2
	}

	ruleSet, err := s.loadRules()
	if err != nil {
		return fail(err.Error())
	}
	endpoints, err := s.Store.ListScanEndpoints(ctx, scanID)
	if err != nil {
		return fail(err.Error())
	}
	work, werr := mutation.BuildWorkList(endpoints, ruleSet)
	if werr != nil {
		return fail(werr.Error())
	}

	if _, mutErr := s.Mutations.Run(ctx, scanID, work); mutErr != nil {
		_ = s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanFailed, engine.PhaseFailed, mutErr.Error())
		return mutErr
	}

	scan, err = s.Store.GetScan(ctx, scanID)
	if err != nil {
		return err
	}
	if errMC := s.advancePhase(ctx, scanID, engine.PhaseMutationComplete, opts); errMC != nil {
		return errMC
	}
	if errFC := s.advancePhase(ctx, scanID, engine.PhaseFindingsComplete, opts); errFC != nil {
		return errFC
	}

	if setErr := s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanCompleted, engine.PhaseFindingsComplete, ""); setErr != nil {
		return setErr
	}
	return nil
}

func baselineSucceeded(scan engine.Scan) bool {
	return scan.BaselineRunStatus == "succeeded" && scan.BaselineEndpointsTotal > 0 &&
		scan.BaselineEndpointsDone >= scan.BaselineEndpointsTotal
}

// reconcileRunPhaseForResume maps persisted baseline success back to run_phase after a failed orchestration
// so resume does not pretend the scan is still waiting on baseline HTTP.
func (s *Service) reconcileRunPhaseForResume(ctx context.Context, scanID string, scan *engine.Scan, opts Options) error {
	if !opts.ResumeRetry || scan.RunPhase != engine.PhaseFailed {
		return nil
	}
	if !baselineSucceeded(*scan) {
		return nil
	}
	if err := s.Store.PatchScanRunPhase(ctx, scanID, engine.PhaseBaselineComplete, ""); err != nil {
		return err
	}
	scan.RunPhase = engine.PhaseBaselineComplete
	scan.RunError = ""
	return nil
}

func (s *Service) loadRules() ([]rules.Rule, error) {
	if s.LoadRules == nil {
		return nil, nil
	}
	return s.LoadRules()
}

func (s *Service) advancePhase(ctx context.Context, scanID string, to engine.ScanRunPhase, opts Options) error {
	if err := ctx.Err(); err != nil {
		_ = s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanFailed, engine.PhaseFailed, err.Error())
		return err
	}
	scan, err := s.Store.GetScan(ctx, scanID)
	if err != nil {
		return err
	}
	if scan.RunPhase == to {
		return nil
	}
	if err := engine.ValidateScanRunTransition(scan.RunPhase, to, opts.ResumeRetry, opts.ForceRerunBaseline); err != nil {
		if canFastForward(scan, to, opts.ForceRerunBaseline) {
			return s.Store.PatchScanRunPhase(ctx, scanID, to, "")
		}
		return err
	}
	return s.Store.PatchScanRunPhase(ctx, scanID, to, "")
}

func scanCanceled(ctx context.Context, st RunStore, scanID string) (bool, error) {
	scan, err := st.GetScan(ctx, scanID)
	if err != nil {
		return false, err
	}
	return scan.Status == engine.ScanCanceled || scan.RunPhase == engine.PhaseCanceled, nil
}

func canFastForward(scan engine.Scan, to engine.ScanRunPhase, forceBaseline bool) bool {
	switch to {
	case engine.PhaseBaselineRunning:
		if scan.RunPhase == engine.PhasePlanned {
			return true
		}
		return forceBaseline && scan.RunPhase == engine.PhaseBaselineComplete && scan.BaselineRunStatus == "succeeded"
	case engine.PhaseBaselineComplete:
		return scan.BaselineRunStatus == "succeeded" && (scan.RunPhase == engine.PhasePlanned || scan.RunPhase == engine.PhaseBaselineRunning)
	case engine.PhaseMutationRunning:
		return scan.BaselineRunStatus == "succeeded" && (scan.RunPhase == engine.PhaseBaselineComplete || scan.RunPhase == engine.PhasePlanned)
	case engine.PhaseMutationComplete:
		return scan.MutationRunStatus == "succeeded"
	case engine.PhaseFindingsComplete:
		return scan.MutationRunStatus == "succeeded"
	default:
		return false
	}
}

func (s *Service) finishCancel(ctx context.Context, scanID string) error {
	_, _ = s.Store.ApplyControl(ctx, scanID, storage.ScanControlCancel)
	_ = s.Store.PatchScanRunPhase(ctx, scanID, engine.PhaseCanceled, "")
	return nil
}
