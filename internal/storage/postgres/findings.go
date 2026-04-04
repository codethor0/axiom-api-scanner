package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const findingsRowSelect = `id, scan_id, rule_id, category, severity, summary,
       COALESCE(NULLIF(evidence_summary, ''), '{}'),
       evidence_uri,
       COALESCE(scan_endpoint_id::text, ''),
       COALESCE(baseline_execution_id::text, ''),
       COALESCE(mutated_execution_id::text, ''),
       assessment_tier, rule_declared_confidence, created_at`

// ListByScanID returns findings for a scan ordered by creation time.
func (s *Store) ListByScanID(ctx context.Context, scanID string, filter storage.FindingListFilter) ([]findings.Finding, error) {
	q := `SELECT ` + findingsRowSelect + ` FROM findings WHERE scan_id = $1`
	args := []any{scanID}
	n := 2
	if t := strings.TrimSpace(filter.AssessmentTier); t != "" {
		q += fmt.Sprintf(" AND assessment_tier = $%d", n)
		args = append(args, t)
		n++
	}
	if t := strings.TrimSpace(filter.Severity); t != "" {
		q += fmt.Sprintf(" AND severity = $%d", n)
		args = append(args, t)
		n++
	}
	if t := strings.TrimSpace(filter.RuleDeclaredConfidence); t != "" {
		q += fmt.Sprintf(" AND rule_declared_confidence = $%d", n)
		args = append(args, strings.ToLower(t))
		n++
	}
	if t := strings.TrimSpace(filter.RuleID); t != "" {
		q += fmt.Sprintf(" AND rule_id = $%d", n)
		args = append(args, t)
	}
	q += " ORDER BY created_at ASC, id ASC"
	rows, err := s.pool.Query(ctx, q, args...)
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

// SummarizeFindingsForScan returns finding totals and bucket counts without loading full rows (one database round-trip).
func (s *Store) SummarizeFindingsForScan(ctx context.Context, scanID string) (storage.FindingsScanSummary, error) {
	const q = `
SELECT
  (SELECT COUNT(*)::int FROM findings WHERE scan_id = $1),
  COALESCE((SELECT jsonb_object_agg(tier, n) FROM (
    SELECT trim(assessment_tier) AS tier, COUNT(*)::int AS n
    FROM findings WHERE scan_id = $1 AND trim(assessment_tier) <> ''
    GROUP BY trim(assessment_tier)
  ) t), '{}'::jsonb),
  COALESCE((SELECT jsonb_object_agg(sev, n) FROM (
    SELECT trim(severity::text) AS sev, COUNT(*)::int AS n
    FROM findings WHERE scan_id = $1 AND trim(severity::text) <> ''
    GROUP BY trim(severity::text)
  ) s), '{}'::jsonb)`
	var total int
	var tierJSON, sevJSON []byte
	if err := s.pool.QueryRow(ctx, q, scanID).Scan(&total, &tierJSON, &sevJSON); err != nil {
		return storage.FindingsScanSummary{}, fmt.Errorf("summarize findings: %w", err)
	}
	out := storage.FindingsScanSummary{Total: total}
	if len(tierJSON) > 0 && string(tierJSON) != "{}" {
		out.ByAssessmentTier = map[string]int{}
		if err := json.Unmarshal(tierJSON, &out.ByAssessmentTier); err != nil {
			return storage.FindingsScanSummary{}, fmt.Errorf("tier buckets: %w", err)
		}
	}
	if len(sevJSON) > 0 && string(sevJSON) != "{}" {
		out.BySeverity = map[string]int{}
		if err := json.Unmarshal(sevJSON, &out.BySeverity); err != nil {
			return storage.FindingsScanSummary{}, fmt.Errorf("severity buckets: %w", err)
		}
	}
	if len(out.ByAssessmentTier) == 0 {
		out.ByAssessmentTier = nil
	}
	if len(out.BySeverity) == 0 {
		out.BySeverity = nil
	}
	return out, nil
}

const sevOrdExpr = `(CASE severity WHEN 'info' THEN 0 WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 WHEN 'critical' THEN 4 ELSE 99 END)`

// ListFindingsPage returns one page of findings using keyset pagination.
func (s *Store) ListFindingsPage(ctx context.Context, scanID string, filter storage.FindingListFilter, opts storage.FindingListPageOptions) (storage.FindingListPage, error) {
	if opts.Limit <= 0 {
		return storage.FindingListPage{}, fmt.Errorf("list findings page: invalid limit")
	}
	sf := strings.TrimSpace(opts.SortField)
	o := strings.TrimSpace(opts.SortOrder)
	if o == "" {
		o = storage.ListSortAsc
	}
	asc := strings.EqualFold(o, storage.ListSortAsc)

	q := `SELECT ` + findingsRowSelect + ` FROM findings WHERE scan_id = $1`
	args := []any{scanID}
	n := 2
	if t := strings.TrimSpace(filter.AssessmentTier); t != "" {
		q += fmt.Sprintf(" AND assessment_tier = $%d", n)
		args = append(args, t)
		n++
	}
	if t := strings.TrimSpace(filter.Severity); t != "" {
		q += fmt.Sprintf(" AND severity = $%d", n)
		args = append(args, t)
		n++
	}
	if t := strings.TrimSpace(filter.RuleDeclaredConfidence); t != "" {
		q += fmt.Sprintf(" AND rule_declared_confidence = $%d", n)
		args = append(args, strings.ToLower(t))
		n++
	}
	if t := strings.TrimSpace(filter.RuleID); t != "" {
		q += fmt.Sprintf(" AND rule_id = $%d", n)
		args = append(args, t)
		n++
	}

	if strings.TrimSpace(opts.Cursor) != "" {
		ts, id, pOrd, sevOrd, err := storage.DecodeListCursor(opts.Cursor, sf, o)
		if err != nil {
			return storage.FindingListPage{}, err
		}
		if pOrd != nil {
			return storage.FindingListPage{}, storage.ErrInvalidListCursor
		}
		switch sf {
		case storage.FindingListSortSeverity:
			if sevOrd == nil {
				return storage.FindingListPage{}, storage.ErrInvalidListCursor
			}
			if asc {
				q += fmt.Sprintf(` AND (`+sevOrdExpr+` > $%d OR (`+sevOrdExpr+` = $%d AND created_at > $%d) OR (`+sevOrdExpr+` = $%d AND created_at = $%d AND id > $%d::uuid))`, n, n, n+1, n, n+1, n+2)
				args = append(args, *sevOrd, ts, id)
			} else {
				q += fmt.Sprintf(` AND (`+sevOrdExpr+` < $%d OR (`+sevOrdExpr+` = $%d AND created_at < $%d) OR (`+sevOrdExpr+` = $%d AND created_at = $%d AND id < $%d::uuid))`, n, n, n+1, n, n+1, n+2)
				args = append(args, *sevOrd, ts, id)
			}
			n += 3
		case storage.FindingListSortCreatedAt:
			if sevOrd != nil {
				return storage.FindingListPage{}, storage.ErrInvalidListCursor
			}
			if asc {
				q += fmt.Sprintf(" AND (created_at > $%d OR (created_at = $%d AND id > $%d::uuid))", n, n, n+1)
				args = append(args, ts, id)
			} else {
				q += fmt.Sprintf(" AND (created_at < $%d OR (created_at = $%d AND id < $%d::uuid))", n, n, n+1)
				args = append(args, ts, id)
			}
			n += 2
		default:
			return storage.FindingListPage{}, storage.ErrInvalidListCursor
		}
	}

	switch sf {
	case storage.FindingListSortSeverity:
		if asc {
			q += " ORDER BY " + sevOrdExpr + " ASC, created_at ASC, id ASC"
		} else {
			q += " ORDER BY " + sevOrdExpr + " DESC, created_at DESC, id DESC"
		}
	case storage.FindingListSortCreatedAt:
		if asc {
			q += " ORDER BY created_at ASC, id ASC"
		} else {
			q += " ORDER BY created_at DESC, id DESC"
		}
	default:
		return storage.FindingListPage{}, storage.ErrInvalidListCursor
	}

	q += fmt.Sprintf(" LIMIT $%d", n)
	args = append(args, opts.Limit+1)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return storage.FindingListPage{}, fmt.Errorf("list findings page: %w", err)
	}
	defer rows.Close()
	var list []findings.Finding
	for rows.Next() {
		f, err := scanFindingRow(rows)
		if err != nil {
			return storage.FindingListPage{}, err
		}
		list = append(list, f)
	}
	if err := rows.Err(); err != nil {
		return storage.FindingListPage{}, err
	}
	hasMore := len(list) > opts.Limit
	if hasMore {
		list = list[:opts.Limit]
	}
	out := storage.FindingListPage{Records: list, HasMore: hasMore}
	if hasMore && len(list) > 0 {
		cur, err := storage.EncodeFindingPageCursor(list[len(list)-1], sf, o)
		if err != nil {
			return storage.FindingListPage{}, err
		}
		out.NextCursor = cur
	}
	return out, nil
}

func scanFindingRow(row pgx.Row) (findings.Finding, error) {
	var f findings.Finding
	var sev string
	var evSum []byte
	err := row.Scan(
		&f.ID,
		&f.ScanID,
		&f.RuleID,
		&f.Category,
		&sev,
		&f.Summary,
		&evSum,
		&f.EvidenceURI,
		&f.ScanEndpointID,
		&f.BaselineExecutionID,
		&f.MutatedExecutionID,
		&f.AssessmentTier,
		&f.RuleDeclaredConfidence,
		&f.CreatedAt,
	)
	if err != nil {
		return findings.Finding{}, err
	}
	f.Severity = findings.Severity(sev)
	if len(evSum) > 0 {
		f.EvidenceSummary = evSum
	}
	return f, nil
}

// GetByEvidenceTuple returns a finding for an exact evidence tuple (dedup key).
func (s *Store) GetByEvidenceTuple(ctx context.Context, scanID, ruleID, scanEndpointID, baselineExecutionID, mutatedExecutionID string) (findings.Finding, error) {
	q := `SELECT ` + findingsRowSelect + ` FROM findings WHERE scan_id = $1 AND rule_id = $2
AND scan_endpoint_id = $3::uuid AND baseline_execution_id = $4::uuid AND mutated_execution_id = $5::uuid`
	f, err := scanFindingRow(s.pool.QueryRow(ctx, q, scanID, ruleID, scanEndpointID, baselineExecutionID, mutatedExecutionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return findings.Finding{}, storage.ErrNotFound
	}
	if err != nil {
		return findings.Finding{}, fmt.Errorf("get finding by evidence: %w", err)
	}
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
	if in.AssessmentTier == "" {
		in.AssessmentTier = "tentative"
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
	evidenceSummary := in.EvidenceSummary
	if len(evidenceSummary) == 0 {
		evidenceSummary = []byte("{}")
	}

	const insF = `
INSERT INTO findings (
  id, scan_id, rule_id, category, severity, summary, evidence_summary, evidence_uri,
  scan_endpoint_id, baseline_execution_id, mutated_execution_id, assessment_tier, rule_declared_confidence
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING ` + findingsRowSelect

	f, err := scanFindingRow(tx.QueryRow(ctx, insF,
		id,
		in.ScanID,
		in.RuleID,
		in.Category,
		string(in.Severity),
		in.Summary,
		evidenceSummary,
		evidenceURI,
		epID,
		baseID,
		mutID,
		in.AssessmentTier,
		in.RuleDeclaredConfidence,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return findings.Finding{}, storage.ErrDuplicateFinding
		}
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
