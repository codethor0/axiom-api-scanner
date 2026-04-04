package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

// ReplaceScanEndpoints replaces all imported endpoints for a scan.
func (s *Store) ReplaceScanEndpoints(ctx context.Context, scanID string, specs []engine.EndpointSpec) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM scan_endpoints WHERE scan_id = $1`, scanID); err != nil {
		return fmt.Errorf("delete endpoints: %w", err)
	}

	const ins = `
INSERT INTO scan_endpoints (scan_id, method, path_template, operation_id, security_scheme_hints, request_content_types, response_content_types, request_body_json)
VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8)`

	for _, sp := range specs {
		hints, err := json.Marshal(sp.SecuritySchemeHints)
		if err != nil {
			return err
		}
		reqCT, err := json.Marshal(sp.RequestContentTypes)
		if err != nil {
			return err
		}
		respCT, err := json.Marshal(sp.ResponseContentTypes)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, ins,
			scanID,
			sp.Method,
			sp.Path,
			sp.OperationID,
			string(hints),
			string(reqCT),
			string(respCT),
			sp.RequestBodyJSON,
		); err != nil {
			return fmt.Errorf("insert endpoint: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// ListScanEndpoints lists endpoints for a scan in deterministic order with optional filters.
func (s *Store) ListScanEndpoints(ctx context.Context, scanID string, filter storage.EndpointListFilter) ([]engine.ScanEndpoint, error) {
	andFrag, fargs := endpointListAndClause(filter, 2)
	q := `
SELECT se.id, se.scan_id, se.method, se.path_template, se.operation_id,
       se.security_scheme_hints::text, se.request_content_types::text, se.response_content_types::text,
       se.request_body_json, se.created_at
FROM scan_endpoints se WHERE se.scan_id = $1` + andFrag + `
ORDER BY se.path_template ASC, se.method ASC`
	args := append([]any{scanID}, fargs...)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}
	defer rows.Close()

	var list []engine.ScanEndpoint
	for rows.Next() {
		var e engine.ScanEndpoint
		var hints, reqC, respC string
		if err := rows.Scan(
			&e.ID,
			&e.ScanID,
			&e.Method,
			&e.PathTemplate,
			&e.OperationID,
			&hints,
			&reqC,
			&respC,
			&e.RequestBodyJSON,
			&e.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(hints), &e.SecuritySchemeHints)
		_ = json.Unmarshal([]byte(reqC), &e.RequestContentTypes)
		_ = json.Unmarshal([]byte(respC), &e.ResponseContentTypes)
		list = append(list, e)
	}
	return list, rows.Err()
}

// ListEndpointInventory lists endpoints with optional persisted execution/finding counts per endpoint row.
func (s *Store) ListEndpointInventory(ctx context.Context, scanID string, filter storage.EndpointListFilter, opt storage.EndpointInventoryOptions) ([]storage.EndpointInventoryEntry, error) {
	andFrag, fargs := endpointListAndClause(filter, 2)
	args := append([]any{scanID}, fargs...)
	if !opt.IncludeSummary {
		eps, err := s.ListScanEndpoints(ctx, scanID, filter)
		if err != nil {
			return nil, err
		}
		out := make([]storage.EndpointInventoryEntry, len(eps))
		for i := range eps {
			out[i] = storage.EndpointInventoryEntry{Endpoint: eps[i]}
		}
		return out, nil
	}
	invSelect := `
WITH b AS (
  SELECT scan_endpoint_id, COUNT(*)::int AS n FROM execution_records
  WHERE scan_id = $1 AND phase = 'baseline' AND scan_endpoint_id IS NOT NULL
  GROUP BY scan_endpoint_id
),
m AS (
  SELECT scan_endpoint_id, COUNT(*)::int AS n FROM execution_records
  WHERE scan_id = $1 AND phase = 'mutated' AND scan_endpoint_id IS NOT NULL
  GROUP BY scan_endpoint_id
),
f AS (
  SELECT scan_endpoint_id, COUNT(*)::int AS n FROM findings
  WHERE scan_id = $1 AND scan_endpoint_id IS NOT NULL
  GROUP BY scan_endpoint_id
)
SELECT se.id, se.scan_id, se.method, se.path_template, se.operation_id,
       se.security_scheme_hints::text, se.request_content_types::text, se.response_content_types::text,
       se.request_body_json, se.created_at,
       COALESCE(b.n, 0)::int, COALESCE(m.n, 0)::int, COALESCE(f.n, 0)::int
FROM scan_endpoints se
LEFT JOIN b ON b.scan_endpoint_id = se.id
LEFT JOIN m ON m.scan_endpoint_id = se.id
LEFT JOIN f ON f.scan_endpoint_id = se.id
WHERE se.scan_id = $1` + andFrag + `
ORDER BY se.path_template ASC, se.method ASC`
	rows, err := s.pool.Query(ctx, invSelect, args...)
	if err != nil {
		return nil, fmt.Errorf("list endpoint inventory: %w", err)
	}
	defer rows.Close()
	var list []storage.EndpointInventoryEntry
	for rows.Next() {
		var e engine.ScanEndpoint
		var hints, reqC, respC string
		var sum storage.EndpointInventorySummary
		if err := rows.Scan(
			&e.ID,
			&e.ScanID,
			&e.Method,
			&e.PathTemplate,
			&e.OperationID,
			&hints,
			&reqC,
			&respC,
			&e.RequestBodyJSON,
			&e.CreatedAt,
			&sum.BaselineExecutionsRecorded,
			&sum.MutationExecutionsRecorded,
			&sum.FindingsRecorded,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(hints), &e.SecuritySchemeHints)
		_ = json.Unmarshal([]byte(reqC), &e.RequestContentTypes)
		_ = json.Unmarshal([]byte(respC), &e.ResponseContentTypes)
		list = append(list, storage.EndpointInventoryEntry{Endpoint: e, Summary: sum})
	}
	return list, rows.Err()
}
