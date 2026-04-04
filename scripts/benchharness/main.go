// Command benchharness prints harness-only strings for benchmark_findings_local.sh (not production).
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
	tier := flag.String("tier", "", "assessment_tier (for outcome-class when count > 0)")
	notesRaw := flag.String("notes", "", "comma-separated assessment_notes (optional)")
	noFinding := flag.Bool("no-finding", false, "emit harness codes for expected absent rate-limit row on httpbin scan")
	outcomeClass := flag.Bool("outcome-class", false, "print BenchmarkOutcomeClass for target+rule+tier+count")
	count := flag.Int("count", -1, "finding row count for rule (for -outcome-class)")
	ruleFamily := flag.Bool("rule-family", false, "print BenchmarkRuleFamilyKey for -rule")
	flag.Parse()

	if *ruleFamily {
		fmt.Print(findings.BenchmarkRuleFamilyKey(*rule))
		return
	}
	if *outcomeClass {
		t := *tier
		if *count <= 0 {
			t = ""
		}
		fmt.Print(findings.BenchmarkOutcomeClass(*target, *rule, t, *count))
		return
	}
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
