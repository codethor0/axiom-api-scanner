package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// CreateScan inserts a new scan in queued status.
func (s *Store) CreateScan(ctx context.Context, in storage.CreateScanInput) (engine.Scan, error) {
	const q = `
INSERT INTO scans (status, target_label, safety_mode, allow_full_execution)
VALUES ($1, $2, $3, $4)
RETURNING id, status, target_label, safety_mode, allow_full_execution, created_at, updated_at`
	row := s.pool.QueryRow(ctx, q,
		string(engine.ScanQueued),
		in.TargetLabel,
		in.SafetyMode,
		in.AllowFullExecution,
	)
	var scan engine.Scan
	if err := row.Scan(
		&scan.ID,
		&scan.Status,
		&scan.TargetLabel,
		&scan.SafetyMode,
		&scan.AllowFullExecution,
		&scan.CreatedAt,
		&scan.UpdatedAt,
	); err != nil {
		return engine.Scan{}, fmt.Errorf("create scan: %w", err)
	}
	return scan, nil
}

// GetScan returns a scan by UUID string.
func (s *Store) GetScan(ctx context.Context, id string) (engine.Scan, error) {
	const q = `
SELECT id, status, target_label, safety_mode, allow_full_execution, created_at, updated_at
FROM scans WHERE id = $1`
	var scan engine.Scan
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&scan.ID,
		&scan.Status,
		&scan.TargetLabel,
		&scan.SafetyMode,
		&scan.AllowFullExecution,
		&scan.CreatedAt,
		&scan.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return engine.Scan{}, storage.ErrNotFound
	}
	if err != nil {
		return engine.Scan{}, fmt.Errorf("get scan: %w", err)
	}
	return scan, nil
}

// ApplyControl updates scan status when the transition is valid.
func (s *Store) ApplyControl(ctx context.Context, id string, action storage.ScanControlAction) (engine.Scan, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return engine.Scan{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	scan, err := getScanForUpdate(ctx, tx, id)
	if err != nil {
		return engine.Scan{}, err
	}
	next, err := nextScanStatus(scan.Status, action)
	if err != nil {
		return engine.Scan{}, err
	}

	const upQ = `
UPDATE scans SET status = $2, updated_at = now() WHERE id = $1
RETURNING id, status, target_label, safety_mode, allow_full_execution, created_at, updated_at`
	var out engine.Scan
	err = tx.QueryRow(ctx, upQ, id, string(next)).Scan(
		&out.ID,
		&out.Status,
		&out.TargetLabel,
		&out.SafetyMode,
		&out.AllowFullExecution,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return engine.Scan{}, storage.ErrNotFound
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "22P02" {
			return engine.Scan{}, storage.ErrNotFound
		}
		return engine.Scan{}, fmt.Errorf("update scan: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return engine.Scan{}, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

func getScanForUpdate(ctx context.Context, tx pgx.Tx, id string) (engine.Scan, error) {
	const q = `
SELECT id, status, target_label, safety_mode, allow_full_execution, created_at, updated_at
FROM scans WHERE id = $1 FOR UPDATE`
	var scan engine.Scan
	err := tx.QueryRow(ctx, q, id).Scan(
		&scan.ID,
		&scan.Status,
		&scan.TargetLabel,
		&scan.SafetyMode,
		&scan.AllowFullExecution,
		&scan.CreatedAt,
		&scan.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return engine.Scan{}, storage.ErrNotFound
	}
	if err != nil {
		return engine.Scan{}, fmt.Errorf("lock scan: %w", err)
	}
	return scan, nil
}

func nextScanStatus(cur engine.ScanStatus, action storage.ScanControlAction) (engine.ScanStatus, error) {
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
	return "", fmt.Errorf("%w from %q via %q", storage.ErrInvalidTransition, cur, action)
}
