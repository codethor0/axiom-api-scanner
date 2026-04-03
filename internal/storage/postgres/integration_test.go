package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/dbmigrate"
	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestScanLifecycle_integration exercises migrations and scan CRUD against a real PostgreSQL URL.
// Requires AXIOM_TEST_DATABASE_URL (for example postgres://user:pass@localhost:5432/axiom_test?sslmode=disable).
// Apply migrations to that database before running, or run from the module root with MIGRATIONS path resolvable.
func TestScanLifecycle_integration(t *testing.T) {
	dsn := os.Getenv("AXIOM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AXIOM_TEST_DATABASE_URL not set; skipping integration test")
	}
	migDir := os.Getenv("AXIOM_TEST_MIGRATIONS_DIR")
	if migDir == "" {
		migDir = "migrations"
	}
	if err := dbmigrate.Up(dsn, migDir); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	s := NewStore(pool)
	scan, err := s.CreateScan(ctx, storage.CreateScanInput{
		TargetLabel:        "integration-target",
		SafetyMode:         "safe",
		AllowFullExecution: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if scan.ID == "" {
		t.Fatal("empty id")
	}

	got, err := s.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TargetLabel != "integration-target" {
		t.Fatalf("got %+v", got)
	}

	scan, err = s.ApplyControl(ctx, scan.ID, storage.ScanControlStart)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Status != engine.ScanRunning {
		t.Fatalf("status %s", scan.Status)
	}

	scan, err = s.ApplyControl(ctx, scan.ID, storage.ScanControlPause)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Status != engine.ScanPaused {
		t.Fatalf("status %s", scan.Status)
	}

	_, err = s.ApplyControl(ctx, scan.ID, storage.ScanControlCancel)
	if err != nil {
		t.Fatal(err)
	}
}
