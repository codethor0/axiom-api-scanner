package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/findings"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

func TestListExecutions_keysetPagination(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, ierr := mem.InsertExecutionRecord(ctx, engine.ExecutionRecord{
			ScanID: scan.ID, Phase: engine.PhaseBaseline,
			RequestMethod: "GET", RequestURL: "https://example.com/", ResponseStatus: 200,
		}); ierr != nil {
			t.Fatal(ierr)
		}
		time.Sleep(3 * time.Millisecond)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	base := srv.URL + "/v1/scans/" + scan.ID + "/executions?limit=2&sort=created_at&order=asc"

	resp1, err := http.Get(base)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp1.StatusCode, b1)
	}
	var p1 ExecutionListResponse
	if uerr := json.Unmarshal(b1, &p1); uerr != nil {
		t.Fatal(uerr)
	}
	if len(p1.Items) != 2 || !p1.Meta.HasMore || p1.Meta.NextCursor == "" {
		t.Fatalf("page1 %+v", p1.Meta)
	}
	if p1.ScanNavigation != NewScanListNavigation(scan.ID) {
		t.Fatalf("scan_navigation %+v", p1.ScanNavigation)
	}

	resp2, err := http.Get(base + "&cursor=" + p1.Meta.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("page2 %d %s", resp2.StatusCode, b2)
	}
	var p2 ExecutionListResponse
	if uerr := json.Unmarshal(b2, &p2); uerr != nil {
		t.Fatal(uerr)
	}
	if len(p2.Items) != 2 {
		t.Fatalf("page2 items %d", len(p2.Items))
	}
	if p2.ScanNavigation != NewScanListNavigation(scan.ID) {
		t.Fatalf("page2 scan_navigation %+v", p2.ScanNavigation)
	}
	if p1.Items[1].ID == p2.Items[0].ID {
		t.Fatal("overlap across pages")
	}
}

func TestListExecutions_rejectsUnsupportedSortAndOffset(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	base := srv.URL + "/v1/scans/" + scan.ID + "/executions"

	resp, err := http.Get(base + "?sort=severity")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 got %d %s", resp.StatusCode, b)
	}

	resp2, err := http.Get(base + "?offset=1")
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("offset: want 400 got %d %s", resp2.StatusCode, b2)
	}
}

func TestListExecutions_invalidCursor(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/executions?cursor=not-a-cursor")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 %s", b)
	}
}

func TestListFindings_severitySortAndPaginationMeta(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "r-high", Category: "c",
		Severity: findings.SeverityHigh, RuleDeclaredConfidence: "high", AssessmentTier: "tentative",
		Summary: "s", Evidence: storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	if _, ferr := mem.CreateFinding(ctx, storage.CreateFindingInput{
		ScanID: scan.ID, RuleID: "r-low", Category: "c",
		Severity: findings.SeverityLow, RuleDeclaredConfidence: "low", AssessmentTier: "tentative",
		Summary: "s", Evidence: storage.CreateEvidenceInput{},
	}); ferr != nil {
		t.Fatal(ferr)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?sort=severity&order=asc&limit=10")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	var env FindingListResponse
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Items) != 2 || env.Items[0].Severity != findings.SeverityLow || env.Items[1].Severity != findings.SeverityHigh {
		t.Fatalf("order %+v", env.Items)
	}
	if env.Meta.Sort != "severity" || env.Meta.Order != "asc" || env.Meta.Limit != 10 {
		t.Fatalf("meta %+v", env.Meta)
	}
	if env.ScanNavigation != NewScanListNavigation(scan.ID) {
		t.Fatalf("scan_navigation %+v", env.ScanNavigation)
	}
}

func TestListFindings_rejectsPhaseSort(t *testing.T) {
	mem := newMemRepositories()
	ctx := context.Background()
	scan, err := mem.CreateScan(ctx, storage.CreateScanInput{TargetLabel: "t", SafetyMode: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testHandler(mem).Routes())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/v1/scans/" + scan.ID + "/findings?sort=phase")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "invalid_sort") {
		t.Fatalf("got %d %s", resp.StatusCode, b)
	}
}
