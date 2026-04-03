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

// FindingRepository lists and fetches finding rows linked to scans.
type FindingRepository interface {
	ListByScanID(ctx context.Context, scanID string) ([]findings.Finding, error)
	GetByID(ctx context.Context, id string) (findings.Finding, error)
}

// EvidenceMetadataRepository loads persisted evidence artifact rows.
type EvidenceMetadataRepository interface {
	GetArtifactByFindingID(ctx context.Context, findingID string) (findings.EvidenceArtifact, error)
}
