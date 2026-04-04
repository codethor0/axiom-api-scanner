package postgres

import (
	"fmt"
	"strings"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

// endpointInventoryExecFindingCTEs counts baseline/mutated execution rows and findings per scan_endpoint for scan_id $1 (reused by inventory list with summary).
const endpointInventoryExecFindingCTEs = `
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
)`

func endpointOrderSQL(sortField, sortOrder string) string {
	asc := strings.EqualFold(sortOrder, storage.ListSortAsc)
	dir := " ASC"
	if !asc {
		dir = " DESC"
	}
	switch strings.TrimSpace(sortField) {
	case storage.EndpointListSortMethod:
		return "se.method" + dir + ", se.path_template" + dir + ", se.id" + dir
	case storage.EndpointListSortCreatedAt:
		return "se.created_at" + dir + ", se.id" + dir
	default:
		return "se.path_template" + dir + ", se.method" + dir + ", se.id" + dir
	}
}

// endpointKeysetSQLAndArgs appends a tuple keyset predicate; argStart is the next $ slot number.
func endpointKeysetSQLAndArgs(sortField, sortOrder string, path, method, id string, createdAt time.Time, argStart int) (frag string, args []any, nextIdx int) {
	asc := strings.EqualFold(sortOrder, storage.ListSortAsc)
	op := ">"
	if !asc {
		op = "<"
	}
	n := argStart
	switch strings.TrimSpace(sortField) {
	case storage.EndpointListSortMethod:
		frag = fmt.Sprintf(` AND (se.method, se.path_template, se.id) %s ($%d::text, $%d::text, $%d::uuid)`, op, n, n+1, n+2)
		args = []any{method, path, id}
		return frag, args, n + 3
	case storage.EndpointListSortCreatedAt:
		frag = fmt.Sprintf(` AND (se.created_at, se.id) %s ($%d::timestamptz, $%d::uuid)`, op, n, n+1)
		args = []any{createdAt, id}
		return frag, args, n + 2
	default:
		frag = fmt.Sprintf(` AND (se.path_template, se.method, se.id) %s ($%d::text, $%d::text, $%d::uuid)`, op, n, n+1, n+2)
		args = []any{path, method, id}
		return frag, args, n + 3
	}
}

// endpointListAndClause returns SQL AND-fragment (empty or " AND cond ...") and bind args starting at argStart.
// Callers append keyset predicates and ORDER BY (see endpointOrderSQL).
func endpointListAndClause(filter storage.EndpointListFilter, argStart int) (string, []any) {
	var conds []string
	args := []any{}
	if m := strings.TrimSpace(filter.Method); m != "" {
		conds = append(conds, fmt.Sprintf("upper(trim(se.method)) = upper($%d::text)", argStart))
		args = append(args, m)
	}
	if filter.DeclaresSecurity != nil {
		if *filter.DeclaresSecurity {
			conds = append(conds, "jsonb_array_length(COALESCE(se.security_scheme_hints, '[]'::jsonb)) > 0")
		} else {
			conds = append(conds, "jsonb_array_length(COALESCE(se.security_scheme_hints, '[]'::jsonb)) = 0")
		}
	}
	if len(conds) == 0 {
		return "", args
	}
	return " AND " + strings.Join(conds, " AND "), args
}
