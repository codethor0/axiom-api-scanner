package storage

import (
	"context"
	"io"
)

// EvidenceStore persists raw evidence blobs (HTTP transcripts, diffs) by stable key.
type EvidenceStore interface {
	Put(ctx context.Context, key string, r io.Reader) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
}
