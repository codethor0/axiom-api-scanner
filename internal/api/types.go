package api

import (
	"time"

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

// EndpointInventorySummaryRead counts persisted baseline/mutated execution_rows and findings rows for one scan_endpoint id.
type EndpointInventorySummaryRead struct {
	BaselineExecutionsRecorded int `json:"baseline_executions_recorded"`
	MutationExecutionsRecorded int `json:"mutation_executions_recorded"`
	FindingsRecorded           int `json:"findings_recorded"`
}

// EndpointRead is one imported OpenAPI operation plus optional inventory summaries (GET .../endpoints).
type EndpointRead struct {
	ID                      string    `json:"id"`
	ScanID                  string    `json:"scan_id"`
	Method                  string    `json:"method"`
	PathTemplate            string    `json:"path_template"`
	OperationID             string    `json:"operation_id,omitempty"`
	SecuritySchemeHints     []string  `json:"security_scheme_hints,omitempty"`
	RequestContentTypes     []string  `json:"request_content_types,omitempty"`
	ResponseContentTypes    []string  `json:"response_content_types,omitempty"`
	RequestBodyJSON         bool      `json:"request_body_json"`
	CreatedAt               time.Time `json:"created_at"`
	DeclaresOpenAPISecurity bool      `json:"declares_openapi_security"`
	Summary                 *EndpointInventorySummaryRead `json:"summary,omitempty"`
}

// EndpointListResponse is the wire envelope for GET /v1/scans/{scanID}/endpoints.
type EndpointListResponse struct {
	Items []EndpointRead `json:"items"`
	Meta  ListPageMeta   `json:"meta"`
}

// ScanControlRequest transitions scan lifecycle state.
type ScanControlRequest struct {
	Action string `json:"action"`
}

// ScanRunProgress counts from the scan row plus inventory-derived endpoint count. "Discovered" is imported `scan_endpoints` row count for this scan (same integer as summary.endpoints_imported). Baseline/mutation counters mirror scan columns; findings_created mirrors scans.findings_count (same integer as summary.findings_created when built together).
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

// Diagnostic category for scan run status (automation; optional on each line). See docs/api.md.
const (
	ScanDiagCategoryBlocked      = "blocked"
	ScanDiagCategorySkipped      = "skipped"
	ScanDiagCategoryInconsistent = "inconsistent"
	ScanDiagCategoryAuthLimit    = "auth_limit"
)

// ScanRunDiagnosticLine is one grounded operator line (code stable for automation; detail human-readable).
type ScanRunDiagnosticLine struct {
	Code     string `json:"code"`
	Detail   string `json:"detail,omitempty"`
	Category string `json:"category,omitempty"`
}

// ScanRunDiagnostics lists narrow, factual skip/block hints derived only from persisted scan columns and endpoint inventory.
// BlockedDetail, SkippedDetail, and ConsistencyDetail are always JSON arrays (possibly empty) on GET/POST .../run/status for a stable wire shape.
type ScanRunDiagnostics struct {
	BlockedDetail       []ScanRunDiagnosticLine `json:"blocked_detail"`
	SkippedDetail       []ScanRunDiagnosticLine `json:"skipped_detail"`
	ConsistencyDetail   []ScanRunDiagnosticLine `json:"consistency_detail"`
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

// ScanRunProtectedRouteCoverage classifies imported operations and persisted HTTP by whether the OpenAPI row declares security schemes.
// HTTP counts come only from execution_records rows with a resolvable scan_endpoint_id; the scanner does not infer auth success beyond recorded status codes.
type ScanRunProtectedRouteCoverage struct {
	ExecutionsRepositoryConfigured bool `json:"executions_repository_configured"`
	// EndpointsWithoutSecurityDeclaration counts imported operations with no securitySchemeHints on the scan_endpoints row.
	EndpointsWithoutSecurityDeclaration int `json:"endpoints_without_security_declaration"`
	EndpointsDeclaringSecurity          int `json:"endpoints_declaring_security"`
	// DeclaredSecurityInBaselineScopeEndpoints is the subset of declared-secure operations that baseline can attempt (GET or JSON POST per baseline runner).
	DeclaredSecurityInBaselineScopeEndpoints  int `json:"declared_security_in_baseline_scope_endpoints"`
	BaselineRecordsWithoutSecurityDeclaration int `json:"baseline_http_records_on_endpoints_without_security_declaration"`
	BaselineRecordsDeclaringSecurity          int `json:"baseline_http_records_on_endpoints_declaring_security"`
	DeclaredSecureBaselineRecordsHTTP401      int `json:"declared_secure_baseline_records_http_401"`
	DeclaredSecureBaselineRecordsHTTP403      int `json:"declared_secure_baseline_records_http_403"`
	DeclaredSecureBaselineRecordsHTTP2xx      int `json:"declared_secure_baseline_records_http_2xx"`
	MutatedRecordsWithoutSecurityDeclaration  int `json:"mutated_http_records_on_endpoints_without_security_declaration"`
	MutatedRecordsDeclaringSecurity           int `json:"mutated_http_records_on_endpoints_declaring_security"`
}

// ScanRunPhaseCounts summarizes one runner line from persisted scan columns (no percentages).
// Total is the planner/runner total (baseline endpoints or mutation candidates). Skipped is max(0, total-completed)
// only when that runner reports status succeeded; otherwise skipped is zero (remaining work is not labeled skipped).
type ScanRunPhaseCounts struct {
	RunStatus string `json:"run_status,omitempty"`
	Total     int    `json:"total"`
	Completed int    `json:"completed"`
	Skipped   int    `json:"skipped"`
}

// ScanRunReadSummary is a compact operator read model: counts from the scan row plus imported endpoint inventory. endpoints_imported equals progress.endpoints_discovered; findings_created equals progress.findings_created (duplicated for operator ergonomics beside baseline/mutation breakdown, not alternate sources).
type ScanRunReadSummary struct {
	EndpointsImported int                `json:"endpoints_imported"`
	Baseline          ScanRunPhaseCounts `json:"baseline"`
	Mutation          ScanRunPhaseCounts `json:"mutation"`
	FindingsCreated   int                `json:"findings_created"`
}

// ScanFindingsSummary aggregates persisted findings rows for this scan (read-only; no new list filters here).
type ScanFindingsSummary struct {
	Total            int            `json:"total"`
	ByAssessmentTier map[string]int `json:"by_assessment_tier,omitempty"`
	BySeverity       map[string]int `json:"by_severity,omitempty"`
}

// ScanRunFamilyCoverageEntry describes whether a V1 rule family had recorded mutated traffic, from rules pack + execution_records only.
type ScanRunFamilyCoverageEntry struct {
	Exercised          bool                   `json:"exercised"`
	RulesInPack        int                    `json:"rules_in_pack"`
	MutatedExecutions  int                    `json:"mutated_executions"`
	NotExercisedReason *ScanRunDiagnosticLine `json:"not_exercised_reason,omitempty"`
	// NotExercisedContributors lists extra grounded factors (auth gap, no planner-eligible endpoints) without duplicating not_exercised_reason.
	NotExercisedContributors []ScanRunDiagnosticLine `json:"not_exercised_contributors,omitempty"`
}

// ScanRunRuleFamilyCoverage maps stable V1 mutation families to coverage signals (see docs/api.md).
type ScanRunRuleFamilyCoverage struct {
	UnavailableReason *ScanRunDiagnosticLine     `json:"unavailable,omitempty"`
	IDORPathOrQuery   ScanRunFamilyCoverageEntry `json:"idor_path_or_query_swap"`
	MassAssignment    ScanRunFamilyCoverageEntry `json:"mass_assignment_privilege_injection"`
	PathNormalization ScanRunFamilyCoverageEntry `json:"path_normalization_bypass"`
	RateLimitHeaders  ScanRunFamilyCoverageEntry `json:"rate_limit_header_rotation"`
}

// ScanRunGuidance lists short, actionable next steps (distinct from diagnostics: guidance is action-oriented; diagnostics are state/facts).
// NextSteps is always a JSON array (possibly empty) on GET/POST .../run/status.
type ScanRunGuidance struct {
	NextSteps []ScanRunDiagnosticLine `json:"next_steps"`
}

// ScanRunStatusResponse is the wire contract for GET /v1/scans/{scanID}/run/status and successful POST .../run.
//
// Canonical (intended for all new clients), in wire order: scan, run, progress, summary, findings_summary, rule_family_coverage, guidance, coverage, protected_route_coverage, diagnostics.
// compatibility is the only legacy mirror; fields there duplicate subset of scan/run for older integrations (see docs/api.md).
type ScanRunStatusResponse struct {
	Scan                   ScanRunScanSummary            `json:"scan"`
	Run                    ScanRunState                  `json:"run"`
	Progress               ScanRunProgress               `json:"progress"`
	Summary                ScanRunReadSummary            `json:"summary"`
	FindingsSummary        ScanFindingsSummary           `json:"findings_summary"`
	RuleFamilyCoverage     ScanRunRuleFamilyCoverage     `json:"rule_family_coverage"`
	Guidance               ScanRunGuidance               `json:"guidance"`
	Coverage               ScanRunCoverage               `json:"coverage"`
	ProtectedRouteCoverage ScanRunProtectedRouteCoverage `json:"protected_route_coverage"`
	Diagnostics            ScanRunDiagnostics            `json:"diagnostics"`
	Compatibility          ScanRunCompatibility          `json:"compatibility"`
}

// ScanRunControlRequest starts, resumes, or cancels a synchronous scan run.
type ScanRunControlRequest struct {
	Action             string `json:"action"`
	ForceRerunBaseline bool   `json:"force_rerun_baseline,omitempty"`
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
	EndpointID   string            `json:"endpoint_id"`
	PathTemplate string            `json:"path_template"`
	Method       string            `json:"method"`
	Decisions    []v1plan.Decision `json:"decisions"`
}

// ListPageMeta is cursor pagination metadata for list endpoints (see docs/api.md).
type ListPageMeta struct {
	Limit      int    `json:"limit"`
	Sort       string `json:"sort"`
	Order      string `json:"order"`
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
}

// ExecutionListResponse is the wire envelope for GET /v1/scans/{scanID}/executions.
type ExecutionListResponse struct {
	Items []ExecutionListItem `json:"items"`
	Meta  ListPageMeta        `json:"meta"`
}

// FindingListResponse is the wire envelope for GET /v1/scans/{scanID}/findings.
type FindingListResponse struct {
	Items []FindingListItem `json:"items"`
	Meta  ListPageMeta      `json:"meta"`
}
