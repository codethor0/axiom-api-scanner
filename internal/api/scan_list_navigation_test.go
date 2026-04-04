package api

import "testing"

func TestNewScanListNavigation_matchesRunStatusDrilldownListPaths(t *testing.T) {
	t.Parallel()
	id := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	nav := NewScanListNavigation(id)
	dd := scanRunDrilldownHints(id)
	if nav.FindingsListPath != dd.FindingsListPath || nav.ExecutionsListPath != dd.ExecutionsListPath || nav.RunStatusPath != dd.RunStatusPath {
		t.Fatalf("nav=%+v drilldown=%+v", nav, dd)
	}
}
