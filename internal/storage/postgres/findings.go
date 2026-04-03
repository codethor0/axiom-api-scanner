package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/jackc/pgx/v5"
)

// ListByScanID returns findings for a scan ordered by creation time.
func (s *Store) ListByScanID(ctx context.Context, scanID string) ([]findings.Finding, error) {
	const q = `
SELECT id, scan_id, rule_id, category, severity, confidence, summary, evidence_uri, created_at
FROM findings WHERE scan_id = $1 ORDER BY created_at ASC`
	rows, err := s.pool.Query(ctx, q, scanID)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	var list []findings.Finding
	for rows.Next() {
		var f findings.Finding
		if err := rows.Scan(
			&f.ID,
			&f.ScanID,
			&f.RuleID,
			&f.Category,
			&f.Severity,
			&f.Confidence,
			&f.Summary,
			&f.EvidenceURI,
			&f.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		list = append(list, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

// GetByID returns a single finding.
func (s *Store) GetByID(ctx context.Context, id string) (findings.Finding, error) {
	const q = `
SELECT id, scan_id, rule_id, category, severity, confidence, summary, evidence_uri, created_at
FROM findings WHERE id = $1`
	var f findings.Finding
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&f.ID,
		&f.ScanID,
		&f.RuleID,
		&f.Category,
		&f.Severity,
		&f.Confidence,
		&f.Summary,
		&f.EvidenceURI,
		&f.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return findings.Finding{}, storage.ErrNotFound
	}
	if err != nil {
		return findings.Finding{}, fmt.Errorf("get finding: %w", err)
	}
	return f, nil
}
