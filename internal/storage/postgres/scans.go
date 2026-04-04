package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/chomechomekitchen/axiom-api-scanner/internal/engine"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const scanReturningColumns = `id, status, target_label, safety_mode, allow_full_execution,
       COALESCE(base_url, ''), COALESCE(auth_headers::text, '{}'),
       COALESCE(baseline_run_status, ''), COALESCE(baseline_run_error, ''),
       baseline_endpoints_total, baseline_endpoints_done,
       COALESCE(mutation_run_status, ''), COALESCE(mutation_run_error, ''),
       mutation_candidates_total, mutation_candidates_done, findings_count,
       created_at, updated_at`

const scanSelect = `SELECT ` + scanReturningColumns + ` FROM scans WHERE id = $1`

func scanFromRow(row pgx.Row) (engine.Scan, error) {
	var scan engine.Scan
	var authText string
	err := row.Scan(
		&scan.ID,
		&scan.Status,
		&scan.TargetLabel,
		&scan.SafetyMode,
		&scan.AllowFullExecution,
		&scan.BaseURL,
		&authText,
		&scan.BaselineRunStatus,
		&scan.BaselineRunError,
		&scan.BaselineEndpointsTotal,
		&scan.BaselineEndpointsDone,
		&scan.MutationRunStatus,
		&scan.MutationRunError,
		&scan.MutationCandidatesTotal,
		&scan.MutationCandidatesDone,
		&scan.FindingsCount,
		&scan.CreatedAt,
		&scan.UpdatedAt,
	)
	if err != nil {
		return engine.Scan{}, err
	}
	scan.AuthHeaders = map[string]string{}
	if authText != "" && authText != "{}" {
		_ = json.Unmarshal([]byte(authText), &scan.AuthHeaders)
	}
	if scan.AuthHeaders == nil {
		scan.AuthHeaders = map[string]string{}
	}
	return scan, nil
}

// CreateScan inserts a new scan in queued status.
func (s *Store) CreateScan(ctx context.Context, in storage.CreateScanInput) (engine.Scan, error) {
	auth := in.AuthHeaders
	if auth == nil {
		auth = map[string]string{}
	}
	authJSON, err := json.Marshal(auth)
	if err != nil {
		return engine.Scan{}, fmt.Errorf("auth json: %w", err)
	}
	q := `INSERT INTO scans (status, target_label, safety_mode, allow_full_execution, base_url, auth_headers)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
RETURNING ` + scanReturningColumns
	row := s.pool.QueryRow(ctx, q,
		string(engine.ScanQueued),
		in.TargetLabel,
		in.SafetyMode,
		in.AllowFullExecution,
		in.BaseURL,
		string(authJSON),
	)
	return scanFromRow(row)
}

// GetScan returns a scan by UUID string.
func (s *Store) GetScan(ctx context.Context, id string) (engine.Scan, error) {
	scan, err := scanFromRow(s.pool.QueryRow(ctx, scanSelect, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return engine.Scan{}, storage.ErrNotFound
	}
	if err != nil {
		return engine.Scan{}, fmt.Errorf("get scan: %w", err)
	}
	return scan, nil
}

// PatchScanTarget updates base URL and optionally replaces auth headers.
func (s *Store) PatchScanTarget(ctx context.Context, id string, in storage.PatchScanTargetInput) (engine.Scan, error) {
	cur, err := s.GetScan(ctx, id)
	if err != nil {
		return engine.Scan{}, err
	}
	base := cur.BaseURL
	if in.BaseURL != nil {
		base = *in.BaseURL
	}
	auth := cur.AuthHeaders
	if in.ReplaceAuth {
		if in.AuthHeaders != nil {
			auth = in.AuthHeaders
		} else {
			auth = map[string]string{}
		}
	}
	authJSON, err := json.Marshal(auth)
	if err != nil {
		return engine.Scan{}, err
	}
	q := `UPDATE scans SET base_url = $2, auth_headers = $3::jsonb, updated_at = now() WHERE id = $1
RETURNING ` + scanReturningColumns
	row := s.pool.QueryRow(ctx, q, id, base, string(authJSON))
	out, err := scanFromRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return engine.Scan{}, storage.ErrNotFound
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "22P02" {
			return engine.Scan{}, storage.ErrNotFound
		}
		return engine.Scan{}, fmt.Errorf("patch scan: %w", err)
	}
	return out, nil
}

// UpdateBaselineState updates baseline counters and status on the scan row.
func (s *Store) UpdateBaselineState(ctx context.Context, scanID string, st storage.BaselineState) error {
	const q = `
UPDATE scans SET
  baseline_run_status = $2,
  baseline_run_error = $3,
  baseline_endpoints_total = $4,
  baseline_endpoints_done = $5,
  updated_at = now()
WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, scanID, st.Status, st.Error, st.Total, st.Done)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// UpdateMutationState updates mutation pass counters and status on the scan row.
func (s *Store) UpdateMutationState(ctx context.Context, scanID string, st storage.MutationState) error {
	const q = `
UPDATE scans SET
  mutation_run_status = $2,
  mutation_run_error = $3,
  mutation_candidates_total = $4,
  mutation_candidates_done = $5,
  updated_at = now()
WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, scanID, st.Status, st.Error, st.Total, st.Done)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
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

	upQ := `UPDATE scans SET status = $2, updated_at = now() WHERE id = $1
RETURNING ` + scanReturningColumns
	var out engine.Scan
	row := tx.QueryRow(ctx, upQ, id, string(next))
	out, err = scanFromRow(row)
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
	const q = scanSelect + ` FOR UPDATE`
	scan, err := scanFromRow(tx.QueryRow(ctx, q, id))
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
