package storage

import (
	"context"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

// CreateScanInput is validated by the API before persistence.
type CreateScanInput struct {
	TargetLabel        string
	SafetyMode         string
	AllowFullExecution bool
	BaseURL            string
	AuthHeaders        map[string]string
}

// ScanControlAction is a user-facing scan lifecycle command.
type ScanControlAction string

const (
	ScanControlStart  ScanControlAction = "start"
	ScanControlPause  ScanControlAction = "pause"
	ScanControlCancel ScanControlAction = "cancel"
)

// ScanRepository persists scan rows and status transitions.
type ScanRepository interface {
	CreateScan(ctx context.Context, in CreateScanInput) (engine.Scan, error)
	GetScan(ctx context.Context, id string) (engine.Scan, error)
	ApplyControl(ctx context.Context, id string, action ScanControlAction) (engine.Scan, error)
}

// ScanTargetRepository updates scope and credentials for a scan.
type ScanTargetRepository interface {
	PatchScanTarget(ctx context.Context, id string, in PatchScanTargetInput) (engine.Scan, error)
}

// PatchScanTargetInput updates target URL and optional auth headers (non-nil fields apply).
type PatchScanTargetInput struct {
	BaseURL     *string
	AuthHeaders map[string]string
	ReplaceAuth bool
}

// BaselineRunStateRepository persists baseline execution progress.
type BaselineRunStateRepository interface {
	UpdateBaselineState(ctx context.Context, scanID string, st BaselineState) error
}

// BaselineState tracks a single baseline pass.
type BaselineState struct {
	Status string
	Error  string
	Total  int
	Done   int
}

// MutationState tracks a single mutation execution pass (sequential candidates).
type MutationState struct {
	Status string
	Error  string
	Total  int
	Done   int
}

// MutationRunStateRepository persists mutation execution progress.
type MutationRunStateRepository interface {
	UpdateMutationState(ctx context.Context, scanID string, st MutationState) error
}

// ExecutionListFilter narrows execution list queries.
type ExecutionListFilter struct {
	Phase          string
	ScanEndpointID string
}

// ExecutionRepository stores HTTP exchange evidence rows.
type ExecutionRepository interface {
	InsertExecutionRecord(ctx context.Context, rec engine.ExecutionRecord) (string, error)
	GetLatestExecution(ctx context.Context, scanID, scanEndpointID string, phase engine.ExecutionPhase) (engine.ExecutionRecord, error)
	ListExecutions(ctx context.Context, scanID string, filter ExecutionListFilter) ([]engine.ExecutionRecord, error)
	GetExecution(ctx context.Context, scanID, executionID string) (engine.ExecutionRecord, error)
}

// EndpointRepository imports and lists persisted OpenAPI endpoints for a scan.
type EndpointRepository interface {
	ReplaceScanEndpoints(ctx context.Context, scanID string, specs []engine.EndpointSpec) error
	ListScanEndpoints(ctx context.Context, scanID string) ([]engine.ScanEndpoint, error)
}

// CreateEvidenceInput is stored with a finding.
type CreateEvidenceInput struct {
	BaselineRequest string
	MutatedRequest  string
	BaselineBody    string
	MutatedBody     string
	DiffSummary     string
}

// CreateFindingInput inserts a confirmed finding and its evidence artifact.
type CreateFindingInput struct {
	ScanID              string
	RuleID              string
	Category            string
	Severity            findings.Severity
	Confidence          string
	Summary             string
	EvidenceSummary     []byte
	ScanEndpointID      string
	BaselineExecutionID string
	MutatedExecutionID  string
	EvidenceURI         string
	FindingStatus       string
	Evidence            CreateEvidenceInput
}

// FindingRepository lists and fetches finding rows linked to scans.
type FindingRepository interface {
	ListByScanID(ctx context.Context, scanID string) ([]findings.Finding, error)
	GetByID(ctx context.Context, id string) (findings.Finding, error)
	CreateFinding(ctx context.Context, in CreateFindingInput) (findings.Finding, error)
}

// EvidenceMetadataRepository loads persisted evidence artifact rows.
type EvidenceMetadataRepository interface {
	GetArtifactByFindingID(ctx context.Context, findingID string) (findings.EvidenceArtifact, error)
}
