package storage

import (
	"context"
	"io"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

// EvidenceStore persists raw evidence blobs (HTTP transcripts, diffs) by stable key.
type EvidenceStore interface {
	Put(ctx context.Context, key string, r io.Reader) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
}

// MetadataStore persists scans, findings, and evidence pointers (PostgreSQL in production).
type MetadataStore interface {
	InsertFinding(ctx context.Context, f findings.Finding) error
	GetFinding(ctx context.Context, id string) (findings.Finding, error)
}
