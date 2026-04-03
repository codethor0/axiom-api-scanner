package api

// CreateScanRequest creates a queued scan with a declared safety posture.
type CreateScanRequest struct {
	TargetLabel        string `json:"target_label"`
	SafetyMode         string `json:"safety_mode"`
	AllowFullExecution bool   `json:"allow_full_execution"`
}

// ScanControlRequest transitions scan lifecycle state.
type ScanControlRequest struct {
	Action string `json:"action"`
}

// ErrorResponse is the stable error envelope for API failures.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail carries a machine-readable code and human-readable message.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// OpenAPIValidateResponse is returned for successful OpenAPI validation.
type OpenAPIValidateResponse struct {
	Status string `json:"status"`
}

// OpenAPIImportResponse lists extracted endpoints from a spec.
type OpenAPIImportResponse struct {
	Endpoints any `json:"endpoints"`
	Count     int `json:"count"`
}
