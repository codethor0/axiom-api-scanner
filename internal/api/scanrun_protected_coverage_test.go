package api

import (
	"testing"

	"github.com/codethor0/axiom-api-scanner/internal/engine"
)

func TestBuildScanRunProtectedRouteCoverage_splitsBaselineBySecurityDeclaration(t *testing.T) {
	pub := engine.ScanEndpoint{ID: "p1", Method: "GET", PathTemplate: "/a"}
	sec := engine.ScanEndpoint{ID: "s1", Method: "GET", PathTemplate: "/b", SecuritySchemeHints: []string{"Bearer"}}
	exec := []engine.ExecutionRecord{
		{Phase: engine.PhaseBaseline, ScanEndpointID: "p1", ResponseStatus: 200},
		{Phase: engine.PhaseBaseline, ScanEndpointID: "s1", ResponseStatus: 401},
		{Phase: engine.PhaseMutated, ScanEndpointID: "s1", RuleID: "r1"},
	}
	pr := buildScanRunProtectedRouteCoverage([]engine.ScanEndpoint{pub, sec}, exec, true)
	if pr.EndpointsWithoutSecurityDeclaration != 1 || pr.EndpointsDeclaringSecurity != 1 {
		t.Fatalf("%+v", pr)
	}
	if pr.BaselineRecordsWithoutSecurityDeclaration != 1 || pr.BaselineRecordsDeclaringSecurity != 1 {
		t.Fatalf("%+v", pr)
	}
	if pr.DeclaredSecureBaselineRecordsHTTP401 != 1 || pr.DeclaredSecureBaselineRecordsHTTP2xx != 0 {
		t.Fatalf("%+v", pr)
	}
	if pr.MutatedRecordsDeclaringSecurity != 1 || pr.MutatedRecordsWithoutSecurityDeclaration != 0 {
		t.Fatalf("%+v", pr)
	}
}

func TestBuildScanRunProtectedRouteCoverage_executionsRepoOff(t *testing.T) {
	pr := buildScanRunProtectedRouteCoverage([]engine.ScanEndpoint{
		{ID: "a", Method: "GET", PathTemplate: "/x"},
	}, nil, false)
	if pr.ExecutionsRepositoryConfigured || pr.EndpointsWithoutSecurityDeclaration != 1 {
		t.Fatalf("%+v", pr)
	}
}
