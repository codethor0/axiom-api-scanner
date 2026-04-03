package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/jackc/pgx/v5"
)

// InsertExecutionRecord persists a baseline or mutated exchange.
func (s *Store) InsertExecutionRecord(ctx context.Context, rec engine.ExecutionRecord) (string, error) {
	reqH, err := json.Marshal(rec.RequestHeaders)
	if err != nil {
		return "", err
	}
	respH, err := json.Marshal(rec.ResponseHeaders)
	if err != nil {
		return "", err
	}

	var epID any
	if rec.ScanEndpointID != "" {
		epID = rec.ScanEndpointID
	}

	const q = `
INSERT INTO execution_records (
  scan_id, scan_endpoint_id, phase, rule_id,
  request_method, request_url, request_headers, request_body,
  response_status, response_headers, response_body, response_content_type, duration_ms
) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10::jsonb, $11, $12, $13)
RETURNING id`

	var id string
	ruleID := rec.RuleID
	if ruleID == "" {
		ruleID = "" // nullable in schema - use empty string, store as null
	}
	row := s.pool.QueryRow(ctx, q,
		rec.ScanID,
		epID,
		string(rec.Phase),
		nullRuleID(ruleID),
		rec.RequestMethod,
		rec.RequestURL,
		string(reqH),
		rec.RequestBody,
		rec.ResponseStatus,
		string(respH),
		rec.ResponseBody,
		rec.ResponseContentType,
		rec.DurationMs,
	)
	if err := row.Scan(&id); err != nil {
		return "", fmt.Errorf("insert execution: %w", err)
	}
	return id, nil
}

func nullRuleID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

const executionSelect = `
SELECT id, scan_id, scan_endpoint_id, phase, rule_id,
       request_method, request_url, request_headers, request_body,
       response_status, response_headers, response_body, response_content_type, duration_ms, created_at
FROM execution_records`

func scanExecution(row pgx.Row) (engine.ExecutionRecord, error) {
	var rec engine.ExecutionRecord
	var epID *string
	var ruleID *string
	var reqH, respH []byte
	err := row.Scan(
		&rec.ID,
		&rec.ScanID,
		&epID,
		&rec.Phase,
		&ruleID,
		&rec.RequestMethod,
		&rec.RequestURL,
		&reqH,
		&rec.RequestBody,
		&rec.ResponseStatus,
		&respH,
		&rec.ResponseBody,
		&rec.ResponseContentType,
		&rec.DurationMs,
		&rec.CreatedAt,
	)
	if err != nil {
		return engine.ExecutionRecord{}, err
	}
	if epID != nil {
		rec.ScanEndpointID = *epID
	}
	if ruleID != nil {
		rec.RuleID = *ruleID
	}
	rec.RequestHeaders = map[string]string{}
	rec.ResponseHeaders = map[string]string{}
	_ = json.Unmarshal(reqH, &rec.RequestHeaders)
	_ = json.Unmarshal(respH, &rec.ResponseHeaders)
	return rec, nil
}

// GetLatestExecution returns the most recent execution row for an endpoint and phase.
func (s *Store) GetLatestExecution(ctx context.Context, scanID, scanEndpointID string, phase engine.ExecutionPhase) (engine.ExecutionRecord, error) {
	q := executionSelect + `
WHERE scan_id = $1 AND scan_endpoint_id = $2 AND phase = $3
ORDER BY created_at DESC LIMIT 1`
	rec, err := scanExecution(s.pool.QueryRow(ctx, q, scanID, scanEndpointID, string(phase)))
	if errors.Is(err, pgx.ErrNoRows) {
		return engine.ExecutionRecord{}, storage.ErrNotFound
	}
	if err != nil {
		return engine.ExecutionRecord{}, fmt.Errorf("latest execution: %w", err)
	}
	return rec, nil
}

// ListExecutions lists execution records for a scan with optional filters.
func (s *Store) ListExecutions(ctx context.Context, scanID string, filter storage.ExecutionListFilter) ([]engine.ExecutionRecord, error) {
	q := executionSelect + ` WHERE scan_id = $1`
	args := []any{scanID}
	n := 2
	if filter.Phase != "" {
		q += fmt.Sprintf(" AND phase = $%d", n)
		args = append(args, filter.Phase)
		n++
	}
	if filter.ScanEndpointID != "" {
		q += fmt.Sprintf(" AND scan_endpoint_id = $%d", n)
		args = append(args, filter.ScanEndpointID)
	}
	q += " ORDER BY created_at ASC"
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list executions: %w", err)
	}
	defer rows.Close()
	var list []engine.ExecutionRecord
	for rows.Next() {
		rec, err := scanExecution(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, rec)
	}
	return list, rows.Err()
}

// GetExecution returns one execution row scoped to a scan.
func (s *Store) GetExecution(ctx context.Context, scanID, executionID string) (engine.ExecutionRecord, error) {
	q := executionSelect + ` WHERE id = $1 AND scan_id = $2`
	rec, err := scanExecution(s.pool.QueryRow(ctx, q, executionID, scanID))
	if errors.Is(err, pgx.ErrNoRows) {
		return engine.ExecutionRecord{}, storage.ErrNotFound
	}
	if err != nil {
		return engine.ExecutionRecord{}, fmt.Errorf("get execution: %w", err)
	}
	return rec, nil
}
