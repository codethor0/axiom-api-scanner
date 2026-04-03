package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDocuments_valid(t *testing.T) {
	const doc = `
id: test.rule
name: Test Rule
category: test
severity: low
confidence: high
safety:
  mode: passive
  destructive: false
target:
  methods: [GET]
  where: query.id
prerequisites:
  - none
mutations:
  - kind: replace_query_param
    param: id
    from: self
    to: other
matchers:
  - kind: status_code_unchanged
references:
  - https://example.com
tags: [test]
`
	rules, err := ParseDocuments([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != "test.rule" {
		t.Fatalf("got %+v", rules)
	}
}

func TestParseDocuments_invalidSafetyMode(t *testing.T) {
	const doc = `
id: bad.safety
name: Bad
category: test
severity: low
confidence: high
safety:
  mode: nuclear
  destructive: true
target:
  methods: [GET]
  where: x
prerequisites: []
mutations:
  - kind: replace_query_param
    param: a
    from: b
    to: c
matchers:
  - kind: status_in
    allowed: [200]
references:
  - r
`
	_, err := ParseDocuments([]byte(doc))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseDocuments_unknownMutationKind(t *testing.T) {
	doc := `
id: bad.mut
name: Bad mut
category: test
severity: low
confidence: high
safety:
  mode: passive
  destructive: false
target:
  methods: [GET]
  where: x
prerequisites: []
mutations:
  - kind: unsupported_mutation_xyz
matchers:
  - kind: status_code_unchanged
references:
  - r
`
	_, err := ParseDocuments([]byte(doc))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("err %v", err)
	}
}

func TestParseDocuments_unknownMatcherKind(t *testing.T) {
	doc := `
id: bad.mat
name: Bad mat
category: test
severity: low
confidence: high
safety:
  mode: passive
  destructive: false
target:
  methods: [GET]
  where: x
prerequisites: []
mutations:
  - kind: replace_query_param
    param: a
    from: b
    to: c
matchers:
  - kind: unsupported_matcher_xyz
references:
  - r
`
	_, err := ParseDocuments([]byte(doc))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadDir_builtin(t *testing.T) {
	root := filepath.Join("..", "..", "rules", "builtin")
	if _, err := os.Stat(root); err != nil {
		t.Skip("rules/builtin not present")
	}
	loader := Loader{}
	rules, err := loader.LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) < 1 {
		t.Fatalf("expected at least one rule, got %d", len(rules))
	}
}
