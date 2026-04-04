package api

import "fmt"

func findingsListPath(scanID string) string {
	return fmt.Sprintf("/v1/scans/%s/findings", scanID)
}

func executionsListPath(scanID string) string {
	return fmt.Sprintf("/v1/scans/%s/executions", scanID)
}

// findingDetailPath is GET /v1/findings/{id} (finding ids are not nested under /scans on the wire).
func findingDetailPath(findingID string) string {
	return fmt.Sprintf("/v1/findings/%s", findingID)
}

func executionDetailPath(scanID, executionID string) string {
	return fmt.Sprintf("/v1/scans/%s/executions/%s", scanID, executionID)
}

// Path-only (no scheme/host) prefixes for scan-scoped list routes. Values are grounded from scan_id.
func scanRunDrilldownHints(scanID string) ScanRunDrilldownHints {
	return ScanRunDrilldownHints{
		ScanID:                 scanID,
		ScanDetailPath:         fmt.Sprintf("/v1/scans/%s", scanID),
		EndpointsInventoryPath: fmt.Sprintf("/v1/scans/%s/endpoints", scanID),
		ExecutionsListPath:     executionsListPath(scanID),
		FindingsListPath:       findingsListPath(scanID),
		RunStatusPath:          fmt.Sprintf("/v1/scans/%s/run/status", scanID),
	}
}

func endpointDrilldownHints(scanID, scanEndpointID string, executionsQuery, findingsQuery string) EndpointDrilldownHints {
	return EndpointDrilldownHints{
		ScanID:                 scanID,
		ScanEndpointID:         scanEndpointID,
		EndpointsInventoryPath: fmt.Sprintf("/v1/scans/%s/endpoints", scanID),
		EndpointDetailPath:     fmt.Sprintf("/v1/scans/%s/endpoints/%s", scanID, scanEndpointID),
		ExecutionsListPath:     executionsListPath(scanID),
		FindingsListPath:       findingsListPath(scanID),
		ExecutionsListQuery:    executionsQuery,
		FindingsListQuery:      findingsQuery,
		RunStatusPath:          fmt.Sprintf("/v1/scans/%s/run/status", scanID),
	}
}
