package rules

import (
	"os"
	"path/filepath"
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
  - kind: noop
matchers:
  - kind: always
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
  - kind: noop
matchers:
  - kind: always
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
