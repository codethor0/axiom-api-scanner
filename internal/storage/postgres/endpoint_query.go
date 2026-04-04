package postgres

import (
	"fmt"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

// endpointListAndClause returns SQL AND-fragment (empty or " AND cond ...") and bind args starting at argStart.
// Caller always appends " ORDER BY se.path_template ASC, se.method ASC".
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
