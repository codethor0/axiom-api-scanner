package v1

import (
	"testing"

	"github.com/chomechomekitchen/axiom-api-scanner/internal/engine"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/rules"
)

func ruleFromDoc(t *testing.T, doc string) rules.Rule {
	t.Helper()
	list, err := rules.ParseDocuments([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return list[0]
}

func TestPlan_idor_eligible(t *testing.T) {
	doc := `
id: r.idor
name: n
category: c
severity: high
confidence: high
safety:
  mode: safe
  destructive: false
target:
  methods: [GET]
  where: path_params.id
prerequisites: []
mutations:
  - kind: replace_path_param
    param: id
    from: self
    to: other
matchers:
  - kind: status_code_unchanged
references:
  - u
tags: []
`
	r := ruleFromDoc(t, doc)
	ep := engine.ScanEndpoint{Method: "GET", PathTemplate: "/items/{id}"}
	dec := Plan(ep, []rules.Rule{r})
	if len(dec) != 1 || !dec[0].Eligible {
		t.Fatalf("%+v", dec)
	}
}

func TestPlan_idor_ineligible_no_brace(t *testing.T) {
	doc := `
id: r.idor2
name: n
category: c
severity: high
confidence: high
safety:
  mode: safe
  destructive: false
target:
  methods: [GET]
  where: path_params.id
prerequisites: []
mutations:
  - kind: replace_path_param
    param: id
    from: self
    to: other
matchers:
  - kind: status_code_unchanged
references:
  - u
tags: []
`
	r := ruleFromDoc(t, doc)
	ep := engine.ScanEndpoint{Method: "GET", PathTemplate: "/items"}
	dec := Plan(ep, []rules.Rule{r})
	if len(dec) != 1 || dec[0].Eligible {
		t.Fatalf("%+v", dec)
	}
}

func TestPlan_mass_assignment_ineligible_no_json_body(t *testing.T) {
	doc := `
id: r.ma
name: n
category: c
severity: high
confidence: high
safety:
  mode: safe
  destructive: false
target:
  methods: [POST]
  where: json_body
prerequisites: []
mutations:
  - kind: merge_json_fields
    fields:
      admin: true
matchers:
  - kind: status_code_unchanged
references:
  - u
tags: []
`
	r := ruleFromDoc(t, doc)
	ep := engine.ScanEndpoint{Method: "POST", PathTemplate: "/x", RequestBodyJSON: false}
	dec := Plan(ep, []rules.Rule{r})
	if len(dec) != 1 || dec[0].Eligible {
		t.Fatalf("%+v", dec)
	}
}

func TestPlan_deterministic_rule_order(t *testing.T) {
	a := ruleFromDoc(t, `
id: z.last
name: n
category: c
severity: high
confidence: high
safety: { mode: safe, destructive: false }
target:
  methods: [GET]
  where: path
prerequisites: []
mutations:
  - kind: path_normalization_variant
    style: trailing_slash
matchers:
  - kind: status_code_unchanged
references: [u]
tags: []
`)
	b := ruleFromDoc(t, `
id: a.first
name: n
category: c
severity: high
confidence: high
safety: { mode: safe, destructive: false }
target:
  methods: [GET]
  where: path
prerequisites: []
mutations:
  - kind: path_normalization_variant
    style: trailing_slash
matchers:
  - kind: status_code_unchanged
references: [u]
tags: []
`)
	ep := engine.ScanEndpoint{Method: "GET", PathTemplate: "/p"}
	dec := Plan(ep, []rules.Rule{a, b})
	if len(dec) != 2 || dec[0].RuleID != "a.first" || dec[1].RuleID != "z.last" {
		t.Fatalf("%+v", dec)
	}
}
