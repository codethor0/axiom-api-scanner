package findings

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Guardrail: files required by scripts/local_stack_preflight.sh and benchmark_findings_local.sh
// must stay in the repository so contributors cloning main can run make benchmark-findings-local.
func TestLocalStackRepoFilesPresent(t *testing.T) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	paths := []string{
		"deploy/e2e/docker-compose.yml",
		"rules",
		"migrations",
		"testdata/e2e/httpbin-openapi.yaml",
		"testdata/e2e/bench-rate-limit-stub.yaml",
		"scripts/local_stack_preflight.sh",
		"scripts/benchmark_findings_local.sh",
		"scripts/e2e_local.sh",
	}
	for _, p := range paths {
		full := filepath.Join(root, p)
		if _, err := os.Stat(full); err != nil {
			t.Fatalf("expected repo path %s (from module root %s): %v", p, root, err)
		}
	}
}
