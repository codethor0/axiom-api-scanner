package api

import (
	"github.com/chomechomekitchen/axiom-api-scanner/internal/engine"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/executor/baseline"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/executor/mutation"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/mutate"
	v1plan "github.com/chomechomekitchen/axiom-api-scanner/internal/plan/v1"
)

// CreateScanRequest creates a queued scan with a declared safety posture.
type CreateScanRequest struct {
	TargetLabel        string            `json:"target_label"`
	SafetyMode         string            `json:"safety_mode"`
	AllowFullExecution bool              `json:"allow_full_execution"`
	BaseURL            string            `json:"base_url,omitempty"`
	AuthHeaders        map[string]string `json:"auth_headers,omitempty"`
}

// PatchScanRequest updates target URL and optional credentials.
type PatchScanRequest struct {
	BaseURL            *string           `json:"base_url,omitempty"`
	AuthHeaders        map[string]string `json:"auth_headers,omitempty"`
	ReplaceAuthHeaders bool              `json:"replace_auth_headers"`
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
	Endpoints []engine.EndpointSpec `json:"endpoints"`
	Count     int                   `json:"count"`
}

// ScanOpenAPIImportResponse is returned when endpoints are persisted for a scan.
type ScanOpenAPIImportResponse struct {
	ScanID    string                `json:"scan_id"`
	Endpoints []engine.EndpointSpec `json:"endpoints"`
	Count     int                   `json:"count"`
}

// BaselineRunAPIResponse wraps the baseline runner result with planning output.
type BaselineRunAPIResponse struct {
	Result             baseline.Result       `json:"result"`
	PlanByEndpoint     []EndpointPlanSummary `json:"plan_by_endpoint"`
	MutationCandidates []mutate.Candidate    `json:"mutation_candidates"`
}

// MutationRunAPIResponse is the outcome of one sequential mutation pass.
type MutationRunAPIResponse struct {
	Result mutation.Result `json:"result"`
}

// EndpointPlanSummary binds planner decisions to one imported endpoint.
type EndpointPlanSummary struct {
	EndpointID   string          `json:"endpoint_id"`
	PathTemplate string          `json:"path_template"`
	Method       string          `json:"method"`
	Decisions    []v1plan.Decision `json:"decisions"`
}
