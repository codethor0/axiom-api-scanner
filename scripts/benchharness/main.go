// Command benchharness prints comma-separated benchmark harness interpretation codes (see findings.BenchmarkHarnessRowNotes).
// Used by scripts/benchmark_findings_local.sh; not a production server.
package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/codethor0/axiom-api-scanner/internal/findings"
)

func main() {
	target := flag.String("target", "", "scan target_label (bench-httpbin-v1-families | bench-rate-stub)")
	rule := flag.String("rule", "", "rule_id")
	tier := flag.String("tier", "", "assessment_tier")
	notesRaw := flag.String("notes", "", "comma-separated assessment_notes (optional)")
	noFinding := flag.Bool("no-finding", false, "emit harness codes for expected absent rate-limit row on httpbin scan")
	flag.Parse()

	if *noFinding {
		if codes := findings.BenchmarkHarnessNoFindingNotes(*target, *rule); len(codes) > 0 {
			fmt.Print(strings.Join(codes, ","))
		}
		return
	}

	notes := splitNotes(*notesRaw)
	codes := findings.BenchmarkHarnessRowNotes(*target, *rule, *tier, notes)
	fmt.Print(strings.Join(codes, ","))
}

func splitNotes(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
