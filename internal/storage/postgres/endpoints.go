package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
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

// ListScanEndpoints lists endpoints for a scan in deterministic order.
func (s *Store) ListScanEndpoints(ctx context.Context, scanID string) ([]engine.ScanEndpoint, error) {
	const q = `
SELECT id, scan_id, method, path_template, operation_id,
       security_scheme_hints::text, request_content_types::text, response_content_types::text,
       request_body_json, created_at
FROM scan_endpoints WHERE scan_id = $1
ORDER BY path_template ASC, method ASC`
	rows, err := s.pool.Query(ctx, q, scanID)
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
