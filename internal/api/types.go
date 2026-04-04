package api

import (
	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/executor/baseline"
	"github.com/codethor0/axiom-api-scanner/internal/executor/mutation"
	"github.com/codethor0/axiom-api-scanner/internal/mutate"
	v1plan "github.com/codethor0/axiom-api-scanner/internal/plan/v1"
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

// ScanRunProgress counts only persisted facts from the scan row and endpoint inventory (no estimates).
type ScanRunProgress struct {
	EndpointsDiscovered         int `json:"endpoints_discovered"`
	BaselineEndpointsTotal      int `json:"baseline_endpoints_total"`
	BaselineExecutionsCompleted int `json:"baseline_executions_completed"`
	MutationCandidatesTotal     int `json:"mutation_candidates_total"`
	MutationExecutionsCompleted int `json:"mutation_executions_completed"`
	FindingsCreated             int `json:"findings_created"`
}

// ScanRunScanSummary is operator-facing scan metadata (no credentials).
type ScanRunScanSummary struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	TargetLabel string `json:"target_label"`
	SafetyMode  string `json:"safety_mode"`
}

// ScanRunState is the canonical persisted orchestration snapshot (one run_phase; runner status lines from storage).
// OrchestratorError is the scan row run_error when run_phase is failed only (pipeline stop reason).
// BaselineRunError / MutationRunError are the last sub-runner messages only when that sub-run status is failed (not duplicated into OrchestratorError here).
type ScanRunState struct {
	Phase             string `json:"phase"`
	OrchestratorError string `json:"orchestrator_error,omitempty"`
	BaselineRunStatus string `json:"baseline_run_status,omitempty"`
	BaselineRunError  string `json:"baseline_run_error,omitempty"`
	MutationRunStatus string `json:"mutation_run_status,omitempty"`
	MutationRunError  string `json:"mutation_run_error,omitempty"`
}

// ScanRunDiagnosticLine is one grounded operator line (code stable for automation; detail human-readable).
type ScanRunDiagnosticLine struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// ScanRunDiagnostics lists narrow, factual skip/block hints derived only from persisted scan columns and endpoint inventory.
type ScanRunDiagnostics struct {
	BlockedDetail       []ScanRunDiagnosticLine `json:"blocked_detail,omitempty"`
	SkippedDetail       []ScanRunDiagnosticLine `json:"skipped_detail,omitempty"`
	PhaseFailedNextStep string                  `json:"phase_failed_next_step,omitempty"`
	ResumeRecommended   bool                    `json:"resume_recommended,omitempty"`
}

// ScanRunCompatibility mirrors a subset of canonical fields for older JSON clients. Prefer scan, run, progress, coverage.
// LastError matches OrchestratorError only (never baseline/mutation sub-messages).
type ScanRunCompatibility struct {
	ScanID     string `json:"scan_id"`
	Phase      string `json:"phase"`
	ScanStatus string `json:"scan_status"`
	LastError  string `json:"last_error,omitempty"`
}

// ScanRunCoverage surfaces operator hints for partial or auth-dependent coverage (no secrets).
type ScanRunCoverage struct {
	AuthHeadersConfigured      bool     `json:"auth_headers_configured"`
	EndpointsDeclaringSecurity int      `json:"endpoints_declaring_security"`
	Hints                      []string `json:"hints,omitempty"`
}

// ScanRunStatusResponse canonical JSON shape for GET/POST .../run/status responses.
// Canonical groups: scan, run, progress, coverage, diagnostics. compatibility is the only non-canonical group (explicit mirror).
type ScanRunStatusResponse struct {
	Scan          ScanRunScanSummary   `json:"scan"`
	Run           ScanRunState         `json:"run"`
	Progress      ScanRunProgress      `json:"progress"`
	Coverage      ScanRunCoverage      `json:"coverage"`
	Diagnostics   ScanRunDiagnostics   `json:"diagnostics"`
	Compatibility ScanRunCompatibility `json:"compatibility"`
}

// ScanRunControlRequest starts, resumes, or cancels a synchronous scan run.
type ScanRunControlRequest struct {
	Action               string `json:"action"`
	ForceRerunBaseline   bool   `json:"force_rerun_baseline,omitempty"`
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
