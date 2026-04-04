package storage

// FindingsScanSummary is an aggregate view of findings for a scan (counts only; same semantics as listing all rows and bucketing).
type FindingsScanSummary struct {
	Total            int
	ByAssessmentTier map[string]int
	BySeverity       map[string]int
}
