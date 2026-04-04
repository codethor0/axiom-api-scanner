package storage

import (
	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

// List pagination defaults and caps for HTTP list endpoints.
const (
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// Execution list sorting (deterministic tie-break: id).
const (
	ExecListSortCreatedAt = "created_at"
	ExecListSortPhase     = "phase"
)

// Finding list sorting (deterministic tie-break: id).
const (
	FindingListSortCreatedAt = "created_at"
	FindingListSortSeverity  = "severity"
)

// Endpoint list sorting (deterministic tie-break: id).
const (
	// EndpointListSortPath orders by path_template, method, id (default; stable import identity).
	EndpointListSortPath = "path"
	// EndpointListSortMethod orders by method, path_template, id.
	EndpointListSortMethod = "method"
	// EndpointListSortCreatedAt orders by created_at, id.
	EndpointListSortCreatedAt = "created_at"
)

// ListSortAsc / ListSortDesc are supported order values.
const (
	ListSortAsc  = "asc"
	ListSortDesc = "desc"
)

// ExecutionListPageOptions configures one executions list HTTP page.
type ExecutionListPageOptions struct {
	Limit     int
	SortField string
	SortOrder string
	Cursor    string
}

// ExecutionListPage is one page of execution records plus continuation.
type ExecutionListPage struct {
	Records    []engine.ExecutionRecord
	NextCursor string
	HasMore    bool
}

// FindingListPageOptions configures one findings list HTTP page.
type FindingListPageOptions struct {
	Limit     int
	SortField string
	SortOrder string
	Cursor    string
}

// FindingListPage is one page of findings plus continuation.
type FindingListPage struct {
	Records    []findings.Finding
	NextCursor string
	HasMore    bool
}

// EndpointListPageOptions configures one endpoint inventory HTTP page.
type EndpointListPageOptions struct {
	Limit     int
	SortField string
	SortOrder string
	Cursor    string
}

// EndpointListPage is one page of endpoint inventory rows plus continuation.
type EndpointListPage struct {
	Records    []EndpointInventoryEntry
	NextCursor string
	HasMore    bool
}
