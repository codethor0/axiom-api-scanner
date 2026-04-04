package api

import "fmt"

// Path-only (no scheme/host) prefixes for scan-scoped list routes. Values are grounded from scan_id.
func scanRunDrilldownHints(scanID string) ScanRunDrilldownHints {
	return ScanRunDrilldownHints{
		ScanID:                 scanID,
		ScanDetailPath:         fmt.Sprintf("/v1/scans/%s", scanID),
		EndpointsInventoryPath: fmt.Sprintf("/v1/scans/%s/endpoints", scanID),
		ExecutionsListPath:     fmt.Sprintf("/v1/scans/%s/executions", scanID),
		FindingsListPath:       fmt.Sprintf("/v1/scans/%s/findings", scanID),
		RunStatusPath:          fmt.Sprintf("/v1/scans/%s/run/status", scanID),
	}
}

func endpointDrilldownHints(scanID, scanEndpointID string, executionsQuery, findingsQuery string) EndpointDrilldownHints {
	return EndpointDrilldownHints{
		ScanID:                 scanID,
		ScanEndpointID:         scanEndpointID,
		EndpointsInventoryPath: fmt.Sprintf("/v1/scans/%s/endpoints", scanID),
		EndpointDetailPath:     fmt.Sprintf("/v1/scans/%s/endpoints/%s", scanID, scanEndpointID),
		ExecutionsListPath:     fmt.Sprintf("/v1/scans/%s/executions", scanID),
		FindingsListPath:       fmt.Sprintf("/v1/scans/%s/findings", scanID),
		ExecutionsListQuery:    executionsQuery,
		FindingsListQuery:      findingsQuery,
		RunStatusPath:          fmt.Sprintf("/v1/scans/%s/run/status", scanID),
	}
}
