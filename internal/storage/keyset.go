package storage

import (
	"strings"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

func executionPhaseRank(rec engine.ExecutionRecord) int {
	if rec.Phase == engine.PhaseBaseline {
		return 0
	}
	return 1
}

func findingSeverityRank(f findings.Finding) int {
	switch f.Severity {
	case findings.SeverityInfo:
		return 0
	case findings.SeverityLow:
		return 1
	case findings.SeverityMedium:
		return 2
	case findings.SeverityHigh:
		return 3
	case findings.SeverityCritical:
		return 4
	default:
		return 99
	}
}

// ExecutionKeysetAfter returns true if rec sorts strictly after the cursor tuple for the given field and direction.
func ExecutionKeysetAfter(rec engine.ExecutionRecord, ts time.Time, id string, phaseOrd *int, sortField string, asc bool) bool {
	id = strings.TrimSpace(id)
	switch sortField {
	case ExecListSortPhase:
		if phaseOrd == nil {
			return false
		}
		pr := executionPhaseRank(rec)
		if asc {
			if pr > *phaseOrd {
				return true
			}
			if pr < *phaseOrd {
				return false
			}
			if rec.CreatedAt.After(ts) {
				return true
			}
			if rec.CreatedAt.Before(ts) {
				return false
			}
			return strings.Compare(rec.ID, id) > 0
		}
		if pr < *phaseOrd {
			return true
		}
		if pr > *phaseOrd {
			return false
		}
		if rec.CreatedAt.Before(ts) {
			return true
		}
		if rec.CreatedAt.After(ts) {
			return false
		}
		return strings.Compare(rec.ID, id) < 0
	default: // created_at
		if asc {
			if rec.CreatedAt.After(ts) {
				return true
			}
			if rec.CreatedAt.Before(ts) {
				return false
			}
			return strings.Compare(rec.ID, id) > 0
		}
		if rec.CreatedAt.Before(ts) {
			return true
		}
		if rec.CreatedAt.After(ts) {
			return false
		}
		return strings.Compare(rec.ID, id) < 0
	}
}

// FindingKeysetAfter returns true if f sorts strictly after the cursor tuple for the given field and direction.
func FindingKeysetAfter(f findings.Finding, ts time.Time, id string, sevOrd *int, sortField string, asc bool) bool {
	id = strings.TrimSpace(id)
	switch sortField {
	case FindingListSortSeverity:
		if sevOrd == nil {
			return false
		}
		sr := findingSeverityRank(f)
		if asc {
			if sr > *sevOrd {
				return true
			}
			if sr < *sevOrd {
				return false
			}
			if f.CreatedAt.After(ts) {
				return true
			}
			if f.CreatedAt.Before(ts) {
				return false
			}
			return strings.Compare(f.ID, id) > 0
		}
		if sr < *sevOrd {
			return true
		}
		if sr > *sevOrd {
			return false
		}
		if f.CreatedAt.Before(ts) {
			return true
		}
		if f.CreatedAt.After(ts) {
			return false
		}
		return strings.Compare(f.ID, id) < 0
	default: // created_at
		if asc {
			if f.CreatedAt.After(ts) {
				return true
			}
			if f.CreatedAt.Before(ts) {
				return false
			}
			return strings.Compare(f.ID, id) > 0
		}
		if f.CreatedAt.Before(ts) {
			return true
		}
		if f.CreatedAt.After(ts) {
			return false
		}
		return strings.Compare(f.ID, id) < 0
	}
}

// ExecutionLess is a deterministic sort order: true if a sorts before b when asc is true.
func ExecutionLess(a, b engine.ExecutionRecord, sortField string, asc bool) bool {
	if asc {
		return executionCmp(a, b, sortField) < 0
	}
	return executionCmp(a, b, sortField) > 0
}

func executionCmp(a, b engine.ExecutionRecord, sortField string) int {
	switch sortField {
	case ExecListSortPhase:
		pa, pb := executionPhaseRank(a), executionPhaseRank(b)
		if pa != pb {
			return pa - pb
		}
	}
	if a.CreatedAt.Before(b.CreatedAt) {
		return -1
	}
	if a.CreatedAt.After(b.CreatedAt) {
		return 1
	}
	return strings.Compare(a.ID, b.ID)
}

// FindingLess is a deterministic sort order for findings.
func FindingLess(a, b findings.Finding, sortField string, asc bool) bool {
	if asc {
		return findingCmp(a, b, sortField) < 0
	}
	return findingCmp(a, b, sortField) > 0
}

// EndpointLess compares two scan endpoints for stable list ordering.
func EndpointLess(a, b engine.ScanEndpoint, sortField string, asc bool) bool {
	if asc {
		return endpointCmp(a, b, sortField) < 0
	}
	return endpointCmp(a, b, sortField) > 0
}

func endpointCmp(a, b engine.ScanEndpoint, sortField string) int {
	switch sortField {
	case EndpointListSortMethod:
		c := strings.Compare(strings.TrimSpace(a.Method), strings.TrimSpace(b.Method))
		if c != 0 {
			return c
		}
		c = strings.Compare(a.PathTemplate, b.PathTemplate)
		if c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	case EndpointListSortCreatedAt:
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	default:
		c := strings.Compare(a.PathTemplate, b.PathTemplate)
		if c != 0 {
			return c
		}
		c = strings.Compare(strings.TrimSpace(a.Method), strings.TrimSpace(b.Method))
		if c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	}
}

// EndpointKeysetAfter returns true if ep sorts strictly after the decoded cursor tuple.
func EndpointKeysetAfter(ep engine.ScanEndpoint, pathTemplate, method, id string, createdAt time.Time, sortField string, asc bool) bool {
	id = strings.TrimSpace(id)
	method = strings.TrimSpace(method)
	pathTemplate = strings.TrimSpace(pathTemplate)
	switch sortField {
	case EndpointListSortMethod:
		if asc {
			cm := strings.Compare(strings.TrimSpace(ep.Method), method)
			if cm > 0 {
				return true
			}
			if cm < 0 {
				return false
			}
			cp := strings.Compare(ep.PathTemplate, pathTemplate)
			if cp > 0 {
				return true
			}
			if cp < 0 {
				return false
			}
			return strings.Compare(ep.ID, id) > 0
		}
		cm := strings.Compare(strings.TrimSpace(ep.Method), method)
		if cm < 0 {
			return true
		}
		if cm > 0 {
			return false
		}
		cp := strings.Compare(ep.PathTemplate, pathTemplate)
		if cp < 0 {
			return true
		}
		if cp > 0 {
			return false
		}
		return strings.Compare(ep.ID, id) < 0
	case EndpointListSortCreatedAt:
		if asc {
			if ep.CreatedAt.After(createdAt) {
				return true
			}
			if ep.CreatedAt.Before(createdAt) {
				return false
			}
			return strings.Compare(ep.ID, id) > 0
		}
		if ep.CreatedAt.Before(createdAt) {
			return true
		}
		if ep.CreatedAt.After(createdAt) {
			return false
		}
		return strings.Compare(ep.ID, id) < 0
	default:
		if asc {
			cp := strings.Compare(ep.PathTemplate, pathTemplate)
			if cp > 0 {
				return true
			}
			if cp < 0 {
				return false
			}
			cm := strings.Compare(strings.TrimSpace(ep.Method), method)
			if cm > 0 {
				return true
			}
			if cm < 0 {
				return false
			}
			return strings.Compare(ep.ID, id) > 0
		}
		cp := strings.Compare(ep.PathTemplate, pathTemplate)
		if cp < 0 {
			return true
		}
		if cp > 0 {
			return false
		}
		cm := strings.Compare(strings.TrimSpace(ep.Method), method)
		if cm < 0 {
			return true
		}
		if cm > 0 {
			return false
		}
		return strings.Compare(ep.ID, id) < 0
	}
}

func findingCmp(a, b findings.Finding, sortField string) int {
	switch sortField {
	case FindingListSortSeverity:
		sa, sb := findingSeverityRank(a), findingSeverityRank(b)
		if sa != sb {
			return sa - sb
		}
	}
	if a.CreatedAt.Before(b.CreatedAt) {
		return -1
	}
	if a.CreatedAt.After(b.CreatedAt) {
		return 1
	}
	return strings.Compare(a.ID, b.ID)
}
