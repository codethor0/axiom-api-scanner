package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const findingsRowSelect = `id, scan_id, rule_id, category, severity, confidence, summary, evidence_uri,
       COALESCE(scan_endpoint_id::text, ''),
       COALESCE(baseline_execution_id::text, ''),
       COALESCE(mutated_execution_id::text, ''),
       finding_status, created_at`

// ListByScanID returns findings for a scan ordered by creation time.
func (s *Store) ListByScanID(ctx context.Context, scanID string) ([]findings.Finding, error) {
	q := `SELECT ` + findingsRowSelect + ` FROM findings WHERE scan_id = $1 ORDER BY created_at ASC`
	rows, err := s.pool.Query(ctx, q, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	var list []findings.Finding
	for rows.Next() {
		f, err := scanFindingRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		list = append(list, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

func scanFindingRow(row pgx.Row) (findings.Finding, error) {
	var f findings.Finding
	var sev string
	err := row.Scan(
		&f.ID,
		&f.ScanID,
		&f.RuleID,
		&f.Category,
		&sev,
		&f.Confidence,
		&f.Summary,
		&f.EvidenceURI,
		&f.ScanEndpointID,
		&f.BaselineExecutionID,
		&f.MutatedExecutionID,
		&f.Status,
		&f.CreatedAt,
	)
	if err != nil {
		return findings.Finding{}, err
	}
	f.Severity = findings.Severity(sev)
	return f, nil
}

// GetByID returns a single finding.
func (s *Store) GetByID(ctx context.Context, id string) (findings.Finding, error) {
	q := `SELECT ` + findingsRowSelect + ` FROM findings WHERE id = $1`
	f, err := scanFindingRow(s.pool.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return findings.Finding{}, storage.ErrNotFound
	}
	if err != nil {
		return findings.Finding{}, fmt.Errorf("get finding: %w", err)
	}
	return f, nil
}

// CreateFinding inserts a finding, evidence artifact, and increments findings_count on the scan.
func (s *Store) CreateFinding(ctx context.Context, in storage.CreateFindingInput) (findings.Finding, error) {
	if in.FindingStatus == "" {
		in.FindingStatus = "confirmed"
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return findings.Finding{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var epID any
	if in.ScanEndpointID != "" {
		epID = in.ScanEndpointID
	}
	var baseID any
	if in.BaselineExecutionID != "" {
		baseID = in.BaselineExecutionID
	}
	var mutID any
	if in.MutatedExecutionID != "" {
		mutID = in.MutatedExecutionID
	}

	id := uuid.NewString()
	evidenceURI := in.EvidenceURI
	if evidenceURI == "" {
		evidenceURI = "/v1/findings/" + id + "/evidence"
	}

	const insF = `
INSERT INTO findings (
  id, scan_id, rule_id, category, severity, confidence, summary, evidence_uri,
  scan_endpoint_id, baseline_execution_id, mutated_execution_id, finding_status
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING ` + findingsRowSelect

	f, err := scanFindingRow(tx.QueryRow(ctx, insF,
		id,
		in.ScanID,
		in.RuleID,
		in.Category,
		string(in.Severity),
		in.Confidence,
		in.Summary,
		evidenceURI,
		epID,
		baseID,
		mutID,
		in.FindingStatus,
	))
	if err != nil {
		return findings.Finding{}, fmt.Errorf("insert finding: %w", err)
	}

	const insE = `
INSERT INTO evidence_artifacts (
  finding_id, baseline_request, mutated_request, baseline_response_body, mutated_response_body, diff_summary
) VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := tx.Exec(ctx, insE,
		f.ID,
		in.Evidence.BaselineRequest,
		in.Evidence.MutatedRequest,
		in.Evidence.BaselineBody,
		in.Evidence.MutatedBody,
		in.Evidence.DiffSummary,
	); err != nil {
		return findings.Finding{}, fmt.Errorf("insert evidence: %w", err)
	}

	const upScan = `UPDATE scans SET findings_count = findings_count + 1, updated_at = now() WHERE id = $1`
	if _, err := tx.Exec(ctx, upScan, in.ScanID); err != nil {
		return findings.Finding{}, fmt.Errorf("bump findings_count: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return findings.Finding{}, err
	}
	return f, nil
}
