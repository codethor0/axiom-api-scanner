package orchestrator

import (
	"context"
	"strings"
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
	"github.com/codethor0/axiom-api-scanner/internal/executor/baseline"
	"github.com/codethor0/axiom-api-scanner/internal/executor/mutation"
	"github.com/codethor0/axiom-api-scanner/internal/storage"
)

// onlyGetScanStore implements RunStore for tests that must not touch persistence beyond GetScan.
type onlyGetScanStore struct {
	scan engine.Scan
}

func (o *onlyGetScanStore) CreateScan(context.Context, storage.CreateScanInput) (engine.Scan, error) {
	panic("CreateScan")
}
func (o *onlyGetScanStore) GetScan(_ context.Context, _ string) (engine.Scan, error) { return o.scan, nil }
func (o *onlyGetScanStore) ApplyControl(context.Context, string, storage.ScanControlAction) (engine.Scan, error) {
	panic("ApplyControl")
}
func (o *onlyGetScanStore) PatchScanRunPhase(context.Context, string, engine.ScanRunPhase, string) error {
	panic("PatchScanRunPhase")
}
func (o *onlyGetScanStore) SetScanStatusAndRunPhase(context.Context, string, engine.ScanStatus, engine.ScanRunPhase, string) error {
	panic("SetScanStatusAndRunPhase")
}
func (o *onlyGetScanStore) PatchScanTarget(context.Context, string, storage.PatchScanTargetInput) (engine.Scan, error) {
	panic("PatchScanTarget")
}
func (o *onlyGetScanStore) ReplaceScanEndpoints(context.Context, string, []engine.EndpointSpec) error {
	panic("ReplaceScanEndpoints")
}
func (o *onlyGetScanStore) ListScanEndpoints(context.Context, string, storage.EndpointListFilter) ([]engine.ScanEndpoint, error) {
	panic("ListScanEndpoints")
}
func (o *onlyGetScanStore) ListScanEndpointsForRunStatus(context.Context, string, storage.EndpointListFilter) ([]engine.ScanEndpoint, error) {
	panic("ListScanEndpointsForRunStatus")
}
func (o *onlyGetScanStore) ListEndpointInventoryPage(context.Context, string, storage.EndpointListFilter, storage.EndpointInventoryOptions, storage.EndpointListPageOptions) (storage.EndpointListPage, error) {
	panic("ListEndpointInventoryPage")
}
func (o *onlyGetScanStore) GetEndpointInventory(context.Context, string, string, storage.EndpointInventoryOptions) (storage.EndpointInventoryEntry, error) {
	panic("GetEndpointInventory")
}

func TestService_Run_nilReceiver(t *testing.T) {
	var s *Service
	if err := s.Run(context.Background(), "550e8400-e29b-41d4-a716-446655440000", Options{}); err == nil {
		t.Fatal("want error")
	}
}

func TestService_Run_incompleteDependencies(t *testing.T) {
	s := &Service{}
	err := s.Run(context.Background(), "550e8400-e29b-41d4-a716-446655440000", Options{})
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("got %v", err)
	}
}

func TestService_Run_completedScanIsNoOp(t *testing.T) {
	id := "550e8400-e29b-41d4-a716-446655440000"
	st := &onlyGetScanStore{
		scan: engine.Scan{
			ID:       id,
			Status:   engine.ScanCompleted,
			RunPhase: engine.PhaseFindingsComplete,
		},
	}
	s := &Service{
		Store:     st,
		Baseline:  baseline.NewRunner(nil),
		Mutations: mutation.NewRunner(nil),
	}
	if err := s.Run(context.Background(), id, Options{ResumeRetry: true}); err != nil {
		t.Fatal(err)
	}
}
