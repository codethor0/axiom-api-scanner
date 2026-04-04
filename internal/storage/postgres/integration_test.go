package postgres

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/chomechomekitchen/axiom-api-scanner/internal/dbmigrate"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/engine"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/findings"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testMigrationsDir returns an absolute path to SQL migrations. When AXIOM_TEST_MIGRATIONS_DIR is unset,
// it resolves repo-root /migrations from this file (tests run with cwd = package dir, not module root).
func testMigrationsDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("AXIOM_TEST_MIGRATIONS_DIR"); d != "" {
		abs, err := filepath.Abs(d)
		if err != nil {
			t.Fatalf("AXIOM_TEST_MIGRATIONS_DIR: %v", err)
		}
		return abs
	}
	_, file, _, ok := runtime.Caller(1) // testMigrationsDir's call site (this file)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	return filepath.Join(repoRoot, "migrations")
}

// TestScanLifecycle_integration exercises migrations and scan CRUD against a real PostgreSQL URL.
// Requires AXIOM_TEST_DATABASE_URL (for example postgres://user:pass@localhost:5432/axiom_test?sslmode=disable).
// Optional: AXIOM_TEST_MIGRATIONS_DIR overrides the repo-root migrations directory.
func TestScanLifecycle_integration(t *testing.T) {
	dsn := os.Getenv("AXIOM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AXIOM_TEST_DATABASE_URL not set; skipping integration test")
	}
	migDir := testMigrationsDir(t)
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
		BaseURL:            "",
		AuthHeaders:        map[string]string{},
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

// TestEndpointReplace_integration verifies OpenAPI re-import deletes prior scan_endpoints rows (no stale inventory).
// Requires AXIOM_TEST_DATABASE_URL and migrations through 000003+ (scan_endpoints).
func TestEndpointReplace_integration(t *testing.T) {
	dsn := os.Getenv("AXIOM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AXIOM_TEST_DATABASE_URL not set; skipping integration test")
	}
	migDir := testMigrationsDir(t)
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
		TargetLabel:        "replace-test",
		SafetyMode:         "safe",
		AllowFullExecution: false,
		BaseURL:            "",
		AuthHeaders:        map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	first := []engine.EndpointSpec{
		{Method: "GET", Path: "/a/{id}"},
		{Method: "GET", Path: "/b"},
	}
	if err = s.ReplaceScanEndpoints(ctx, scan.ID, first); err != nil {
		t.Fatal(err)
	}
	list1, err := s.ListScanEndpoints(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list1) != 2 {
		t.Fatalf("want 2 endpoints, got %d", len(list1))
	}
	oldIDs := map[string]bool{list1[0].ID: true, list1[1].ID: true}

	second := []engine.EndpointSpec{
		{Method: "POST", Path: "/c"},
	}
	if err = s.ReplaceScanEndpoints(ctx, scan.ID, second); err != nil {
		t.Fatal(err)
	}
	list2, err := s.ListScanEndpoints(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list2) != 1 {
		t.Fatalf("want 1 endpoint after replace, got %d", len(list2))
	}
	if list2[0].Method != "POST" || list2[0].PathTemplate != "/c" {
		t.Fatalf("got %+v", list2[0])
	}
	for _, ep := range list2 {
		if oldIDs[ep.ID] {
			t.Fatalf("stale endpoint id %s still present after full replace", ep.ID)
		}
	}
}

// TestFindingWrite_integration exercises CreateFinding, evidence row, and findings_count after migration 000004.
func TestFindingWrite_integration(t *testing.T) {
	dsn := os.Getenv("AXIOM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AXIOM_TEST_DATABASE_URL not set; skipping integration test")
	}
	migDir := testMigrationsDir(t)
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
		TargetLabel:        "finding-test",
		SafetyMode:         "safe",
		AllowFullExecution: false,
		BaseURL:            "http://127.0.0.1:9",
		AuthHeaders:        map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err = s.ReplaceScanEndpoints(ctx, scan.ID, []engine.EndpointSpec{
		{Method: "GET", Path: "/x"},
	}); err != nil {
		t.Fatal(err)
	}
	eps, err := s.ListScanEndpoints(ctx, scan.ID)
	if err != nil || len(eps) != 1 {
		t.Fatal(eps, err)
	}
	ep := eps[0]

	bid, err := s.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID:              scan.ID,
		ScanEndpointID:      ep.ID,
		Phase:               engine.PhaseBaseline,
		RequestMethod:       "GET",
		RequestURL:          "http://127.0.0.1:9/x",
		RequestHeaders:      map[string]string{},
		ResponseStatus:      200,
		ResponseHeaders:     map[string]string{"Content-Type": "application/json"},
		ResponseBody:        `{}`,
		ResponseContentType: "application/json",
	})
	if err != nil {
		t.Fatal(err)
	}
	mid, err := s.InsertExecutionRecord(ctx, engine.ExecutionRecord{
		ScanID:              scan.ID,
		ScanEndpointID:      ep.ID,
		Phase:               engine.PhaseMutated,
		RuleID:              "rule.integration",
		RequestMethod:       "GET",
		RequestURL:          "http://127.0.0.1:9/x",
		RequestHeaders:      map[string]string{},
		ResponseStatus:      200,
		ResponseHeaders:     map[string]string{"Content-Type": "application/json"},
		ResponseBody:        `{}`,
		ResponseContentType: "application/json",
	})
	if err != nil {
		t.Fatal(err)
	}

	fin, err := s.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID:                 scan.ID,
		RuleID:                 "rule.integration",
		Category:               "test",
		Severity:               findings.SeverityLow,
		RuleDeclaredConfidence: "high",
		AssessmentTier:         "confirmed",
		Summary:                "integration finding",
		ScanEndpointID:         ep.ID,
		BaselineExecutionID:    bid,
		MutatedExecutionID:     mid,
		Evidence: storage.CreateEvidenceInput{
			BaselineRequest: `{"method":"GET"}`,
			MutatedRequest:  `{"method":"GET"}`,
			BaselineBody:    `{}`,
			MutatedBody:     `{}`,
			DiffSummary:     "all_matchers_passed",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fin.ID == "" || fin.EvidenceURI == "" {
		t.Fatalf("finding %+v", fin)
	}
	if fin.BaselineExecutionID != bid || fin.MutatedExecutionID != mid {
		t.Fatalf("linkage %+v", fin)
	}

	got, err := s.GetByID(ctx, fin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary != "integration finding" {
		t.Fatal(got)
	}
	if len(got.EvidenceSummary) == 0 {
		t.Fatal("expected default evidence_summary from insert")
	}
	ev, err := s.GetArtifactByFindingID(ctx, fin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ev.DiffSummary != "all_matchers_passed" {
		t.Fatal(ev)
	}

	scan2, err := s.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scan2.FindingsCount != 1 {
		t.Fatalf("findings_count want 1 got %d", scan2.FindingsCount)
	}

	list, err := s.ListExecutions(ctx, scan.ID, storage.ExecutionListFilter{})
	if err != nil || len(list) != 2 {
		t.Fatalf("executions %+v err %v", list, err)
	}
	one, err := s.GetExecution(ctx, scan.ID, bid)
	if err != nil {
		t.Fatal(err)
	}
	if one.ID != bid || one.Phase != engine.PhaseBaseline {
		t.Fatal(one)
	}
}
