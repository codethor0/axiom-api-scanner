package engine

// ExecutionRunTally is a minimal projection of execution_records for scan run status aggregation
// (protected-route coverage, rule-family counts, consistency). It excludes bodies and headers.
type ExecutionRunTally struct {
	ScanEndpointID string
	Phase          ExecutionPhase
	ResponseStatus int
	RuleID         string
}
