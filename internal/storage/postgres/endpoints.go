package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
ORDER BY se.path_template ASC, se.method ASC, se.id ASC`
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

// ListScanEndpointsForRunStatus loads planner and protected-route fields only (no request/response content-type JSON).
func (s *Store) ListScanEndpointsForRunStatus(ctx context.Context, scanID string, filter storage.EndpointListFilter) ([]engine.ScanEndpoint, error) {
	andFrag, fargs := endpointListAndClause(filter, 2)
	q := `
SELECT se.id, se.scan_id, se.method, se.path_template, se.operation_id,
       se.security_scheme_hints::text, se.request_body_json, se.created_at
FROM scan_endpoints se WHERE se.scan_id = $1` + andFrag + `
ORDER BY se.path_template ASC, se.method ASC, se.id ASC`
	args := append([]any{scanID}, fargs...)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list endpoints for run status: %w", err)
	}
	defer rows.Close()

	var list []engine.ScanEndpoint
	for rows.Next() {
		var e engine.ScanEndpoint
		var hints string
		if err := rows.Scan(
			&e.ID,
			&e.ScanID,
			&e.Method,
			&e.PathTemplate,
			&e.OperationID,
			&hints,
			&e.RequestBodyJSON,
			&e.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(hints), &e.SecuritySchemeHints)
		list = append(list, e)
	}
	return list, rows.Err()
}

// ListEndpointInventoryPage returns one page of endpoint inventory using opaque keyset cursors (same family as executions/findings lists).
func (s *Store) ListEndpointInventoryPage(ctx context.Context, scanID string, filter storage.EndpointListFilter, opt storage.EndpointInventoryOptions, opts storage.EndpointListPageOptions) (storage.EndpointListPage, error) {
	if opts.Limit <= 0 {
		return storage.EndpointListPage{}, fmt.Errorf("list endpoint inventory page: invalid limit")
	}
	sf := strings.TrimSpace(opts.SortField)
	if sf == "" {
		sf = storage.EndpointListSortPath
	}
	o := strings.TrimSpace(opts.SortOrder)
	if o == "" {
		o = storage.ListSortAsc
	}
	switch sf {
	case storage.EndpointListSortPath, storage.EndpointListSortMethod, storage.EndpointListSortCreatedAt:
	default:
		return storage.EndpointListPage{}, fmt.Errorf("list endpoint inventory page: invalid sort")
	}

	andFrag, fargs := endpointListAndClause(filter, 2)
	args := append([]any{scanID}, fargs...)
	n := 2 + len(fargs)

	var baseQ string
	if opt.IncludeSummary {
		baseQ = endpointInventoryExecFindingCTEs + `
SELECT se.id, se.scan_id, se.method, se.path_template, se.operation_id,
       se.security_scheme_hints::text, se.request_content_types::text, se.response_content_types::text,
       se.request_body_json, se.created_at,
       COALESCE(b.n, 0)::int, COALESCE(m.n, 0)::int, COALESCE(f.n, 0)::int
FROM scan_endpoints se
LEFT JOIN b ON b.scan_endpoint_id = se.id
LEFT JOIN m ON m.scan_endpoint_id = se.id
LEFT JOIN f ON f.scan_endpoint_id = se.id
WHERE se.scan_id = $1` + andFrag
	} else {
		baseQ = `
SELECT se.id, se.scan_id, se.method, se.path_template, se.operation_id,
       se.security_scheme_hints::text, se.request_content_types::text, se.response_content_types::text,
       se.request_body_json, se.created_at
FROM scan_endpoints se
WHERE se.scan_id = $1` + andFrag
	}

	q := baseQ
	if strings.TrimSpace(opts.Cursor) != "" {
		path, method, id, ca, err := storage.DecodeEndpointCursor(opts.Cursor, sf, o)
		if err != nil {
			return storage.EndpointListPage{}, err
		}
		frag, cargs, nextN := endpointKeysetSQLAndArgs(sf, o, path, method, id, ca, n)
		q += frag
		args = append(args, cargs...)
		n = nextN
	}

	q += " ORDER BY " + endpointOrderSQL(sf, o)
	q += fmt.Sprintf(" LIMIT $%d", n)
	args = append(args, opts.Limit+1)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return storage.EndpointListPage{}, fmt.Errorf("list endpoint inventory page: %w", err)
	}
	defer rows.Close()

	var list []storage.EndpointInventoryEntry
	for rows.Next() {
		var hints, reqC, respC string
		var ent storage.EndpointInventoryEntry
		if opt.IncludeSummary {
			var sum storage.EndpointInventorySummary
			if err := rows.Scan(
				&ent.Endpoint.ID,
				&ent.Endpoint.ScanID,
				&ent.Endpoint.Method,
				&ent.Endpoint.PathTemplate,
				&ent.Endpoint.OperationID,
				&hints,
				&reqC,
				&respC,
				&ent.Endpoint.RequestBodyJSON,
				&ent.Endpoint.CreatedAt,
				&sum.BaselineExecutionsRecorded,
				&sum.MutationExecutionsRecorded,
				&sum.FindingsRecorded,
			); err != nil {
				return storage.EndpointListPage{}, err
			}
			ent.Summary = sum
		} else {
			if err := rows.Scan(
				&ent.Endpoint.ID,
				&ent.Endpoint.ScanID,
				&ent.Endpoint.Method,
				&ent.Endpoint.PathTemplate,
				&ent.Endpoint.OperationID,
				&hints,
				&reqC,
				&respC,
				&ent.Endpoint.RequestBodyJSON,
				&ent.Endpoint.CreatedAt,
			); err != nil {
				return storage.EndpointListPage{}, err
			}
		}
		_ = json.Unmarshal([]byte(hints), &ent.Endpoint.SecuritySchemeHints)
		_ = json.Unmarshal([]byte(reqC), &ent.Endpoint.RequestContentTypes)
		_ = json.Unmarshal([]byte(respC), &ent.Endpoint.ResponseContentTypes)
		list = append(list, ent)
	}
	if err := rows.Err(); err != nil {
		return storage.EndpointListPage{}, err
	}

	hasMore := len(list) > opts.Limit
	if hasMore {
		list = list[:opts.Limit]
	}
	out := storage.EndpointListPage{Records: list, HasMore: hasMore}
	if hasMore && len(list) > 0 {
		cur, err := storage.EncodeEndpointPageCursor(sf, o, list[len(list)-1])
		if err != nil {
			return storage.EndpointListPage{}, err
		}
		out.NextCursor = cur
	}
	return out, nil
}

// GetEndpointInventory returns one scan_endpoints row for the scan, optionally with inventory summary joins.
func (s *Store) GetEndpointInventory(ctx context.Context, scanID, endpointID string, opt storage.EndpointInventoryOptions) (storage.EndpointInventoryEntry, error) {
	if _, err := uuid.Parse(endpointID); err != nil {
		return storage.EndpointInventoryEntry{}, fmt.Errorf("get endpoint inventory: %w", err)
	}
	var hints, reqC, respC string
	var ent storage.EndpointInventoryEntry

	if opt.IncludeSummary {
		q := endpointInventoryExecFindingCTEs + `
SELECT se.id, se.scan_id, se.method, se.path_template, se.operation_id,
       se.security_scheme_hints::text, se.request_content_types::text, se.response_content_types::text,
       se.request_body_json, se.created_at,
       COALESCE(b.n, 0)::int, COALESCE(m.n, 0)::int, COALESCE(f.n, 0)::int
FROM scan_endpoints se
LEFT JOIN b ON b.scan_endpoint_id = se.id
LEFT JOIN m ON m.scan_endpoint_id = se.id
LEFT JOIN f ON f.scan_endpoint_id = se.id
WHERE se.scan_id = $1 AND se.id = $2`
		var sum storage.EndpointInventorySummary
		err := s.pool.QueryRow(ctx, q, scanID, endpointID).Scan(
			&ent.Endpoint.ID,
			&ent.Endpoint.ScanID,
			&ent.Endpoint.Method,
			&ent.Endpoint.PathTemplate,
			&ent.Endpoint.OperationID,
			&hints,
			&reqC,
			&respC,
			&ent.Endpoint.RequestBodyJSON,
			&ent.Endpoint.CreatedAt,
			&sum.BaselineExecutionsRecorded,
			&sum.MutationExecutionsRecorded,
			&sum.FindingsRecorded,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.EndpointInventoryEntry{}, storage.ErrNotFound
		}
		if err != nil {
			return storage.EndpointInventoryEntry{}, fmt.Errorf("get endpoint inventory: %w", err)
		}
		ent.Summary = sum
	} else {
		q := `
SELECT se.id, se.scan_id, se.method, se.path_template, se.operation_id,
       se.security_scheme_hints::text, se.request_content_types::text, se.response_content_types::text,
       se.request_body_json, se.created_at
FROM scan_endpoints se
WHERE se.scan_id = $1 AND se.id = $2`
		err := s.pool.QueryRow(ctx, q, scanID, endpointID).Scan(
			&ent.Endpoint.ID,
			&ent.Endpoint.ScanID,
			&ent.Endpoint.Method,
			&ent.Endpoint.PathTemplate,
			&ent.Endpoint.OperationID,
			&hints,
			&reqC,
			&respC,
			&ent.Endpoint.RequestBodyJSON,
			&ent.Endpoint.CreatedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.EndpointInventoryEntry{}, storage.ErrNotFound
		}
		if err != nil {
			return storage.EndpointInventoryEntry{}, fmt.Errorf("get endpoint inventory: %w", err)
		}
	}
	_ = json.Unmarshal([]byte(hints), &ent.Endpoint.SecuritySchemeHints)
	_ = json.Unmarshal([]byte(reqC), &ent.Endpoint.RequestContentTypes)
	_ = json.Unmarshal([]byte(respC), &ent.Endpoint.ResponseContentTypes)
	return ent, nil
}
