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
	Baseline  *baseline.Runner
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
		if _, err := s.Store.ApplyControl(ctx, scanID, storage.ScanControlStart); err != nil && !errors.Is(err, storage.ErrInvalidTransition) {
			return err
		}
		scan, err = s.Store.GetScan(ctx, scanID)
		if err != nil {
			return err
		}
	}

	if err := s.advancePhase(ctx, scanID, engine.PhaseBaselineRunning, opts.ResumeRetry); err != nil {
		return err
	}
	if canceled, err := scanCanceled(ctx, s.Store, scanID); err != nil {
		return err
	} else if canceled {
		return s.finishCancel(ctx, scanID)
	}
	if err := ctx.Err(); err != nil {
		_ = s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanFailed, engine.PhaseFailed, err.Error())
		return err
	}

	bOpts := baseline.RunOptions{Force: opts.ForceRerunBaseline}
	if _, err := s.Baseline.RunWithOptions(ctx, scanID, bOpts); err != nil {
		_ = s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanFailed, engine.PhaseFailed, err.Error())
		return err
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

	if err := s.advancePhase(ctx, scanID, engine.PhaseBaselineComplete, opts.ResumeRetry); err != nil {
		return err
	}
	if err := s.advancePhase(ctx, scanID, engine.PhaseMutationRunning, opts.ResumeRetry); err != nil {
		return err
	}
	if canceled, err := scanCanceled(ctx, s.Store, scanID); err != nil {
		return err
	} else if canceled {
		return s.finishCancel(ctx, scanID)
	}
	if err := ctx.Err(); err != nil {
		_ = s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanFailed, engine.PhaseFailed, err.Error())
		return err
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

	if _, err := s.Mutations.Run(ctx, scanID, work); err != nil {
		_ = s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanFailed, engine.PhaseFailed, err.Error())
		return err
	}

	scan, err = s.Store.GetScan(ctx, scanID)
	if err != nil {
		return err
	}
	if err := s.advancePhase(ctx, scanID, engine.PhaseMutationComplete, opts.ResumeRetry); err != nil {
		return err
	}
	if err := s.advancePhase(ctx, scanID, engine.PhaseFindingsComplete, opts.ResumeRetry); err != nil {
		return err
	}

	if err := s.Store.SetScanStatusAndRunPhase(ctx, scanID, engine.ScanCompleted, engine.PhaseFindingsComplete, ""); err != nil {
		return err
	}
	return nil
}

func (s *Service) loadRules() ([]rules.Rule, error) {
	if s.LoadRules == nil {
		return nil, nil
	}
	return s.LoadRules()
}

func (s *Service) advancePhase(ctx context.Context, scanID string, to engine.ScanRunPhase, resumeRetry bool) error {
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
	if err := engine.ValidateScanRunTransition(scan.RunPhase, to, resumeRetry); err != nil {
		if canFastForward(scan, to) {
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

func canFastForward(scan engine.Scan, to engine.ScanRunPhase) bool {
	switch to {
	case engine.PhaseBaselineRunning:
		return scan.RunPhase == engine.PhasePlanned
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
