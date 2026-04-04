package storage

import (
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

// ScanEndpointMatchesListFilter reports whether an imported endpoint row matches optional read filters.
func ScanEndpointMatchesListFilter(ep engine.ScanEndpoint, f EndpointListFilter) bool {
	if m := strings.TrimSpace(f.Method); m != "" {
		if !strings.EqualFold(strings.TrimSpace(ep.Method), m) {
			return false
		}
	}
	if f.DeclaresSecurity != nil {
		has := len(ep.SecuritySchemeHints) > 0
		if *f.DeclaresSecurity != has {
			return false
		}
	}
	return true
}

// EndpointListFilter narrows read-only endpoint inventory (optional fields; zero value = no filter).
type EndpointListFilter struct {
	// Method is matched case-insensitively after trimming; empty means no filter.
	Method string
	// DeclaresSecurity: nil = no filter; true = endpoints with non-empty OpenAPI security hints on import; false = no hints.
	DeclaresSecurity *bool
}

// EndpointInventorySummary counts persisted rows for one scan_endpoint_id (execution and finding facts only).
type EndpointInventorySummary struct {
	BaselineExecutionsRecorded int
	MutationExecutionsRecorded int
	FindingsRecorded           int
}

// EndpointInventoryEntry is one imported operation plus inventory summaries.
type EndpointInventoryEntry struct {
	Endpoint engine.ScanEndpoint
	Summary  EndpointInventorySummary
}

// EndpointInventoryOptions configures endpoint inventory list pages (summary joins are skipped when IncludeSummary is false).
type EndpointInventoryOptions struct {
	IncludeSummary bool
}
