package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/jackc/pgx/v5"
)

// GetArtifactByFindingID returns the evidence artifact row for a finding (if any).
func (s *Store) GetArtifactByFindingID(ctx context.Context, findingID string) (findings.EvidenceArtifact, error) {
	const q = `
SELECT id, finding_id, baseline_request, mutated_request, baseline_response_body, mutated_response_body, diff_summary, created_at
FROM evidence_artifacts WHERE finding_id = $1 LIMIT 1`
	var e findings.EvidenceArtifact
	err := s.pool.QueryRow(ctx, q, findingID).Scan(
		&e.ID,
		&e.FindingID,
		&e.BaselineRequest,
		&e.MutatedRequest,
		&e.BaselineBody,
		&e.MutatedBody,
		&e.DiffSummary,
		&e.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return findings.EvidenceArtifact{}, storage.ErrNotFound
	}
	if err != nil {
		return findings.EvidenceArtifact{}, fmt.Errorf("get evidence: %w", err)
	}
	return e, nil
}
