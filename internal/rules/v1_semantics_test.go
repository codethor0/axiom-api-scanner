package rules

import "testing"

func TestValidateSafePassiveV1_rejectsMultipleMutations(t *testing.T) {
	const doc = `
id: two.mut
name: n
category: c
severity: high
confidence: high
safety:
  mode: safe
  destructive: false
target:
  methods: [GET]
  where: path
prerequisites: []
mutations:
  - kind: replace_path_param
    param: id
    from: a
    to: b
  - kind: path_normalization_variant
    style: trailing_slash
matchers:
  - kind: status_code_unchanged
references:
  - https://example.com
tags: []
`
	_, err := ParseDocuments([]byte(doc))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_conflictingMatchers(t *testing.T) {
	const doc = `
id: conflict
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
    from: a
    to: b
matchers:
  - kind: status_code_unchanged
  - kind: status_differs_from_baseline
references:
  - https://example.com
tags: []
`
	_, err := ParseDocuments([]byte(doc))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_rateLimitFamily_requiresHeaderMatcher(t *testing.T) {
	const doc = `
id: rl.bad
name: n
category: c
severity: high
confidence: high
safety:
  mode: safe
  destructive: false
target:
  methods: [GET]
  where: path
prerequisites: []
mutations:
  - kind: rotate_request_headers
    headers:
      - name: X-Forwarded-For
        value: "127.0.0.2"
matchers:
  - kind: status_code_unchanged
references:
  - https://example.com
tags: []
`
	_, err := ParseDocuments([]byte(doc))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_idor_rejectsHeaderMatchers(t *testing.T) {
	const doc = `
id: idor.hdr
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
    from: a
    to: b
matchers:
  - kind: status_code_unchanged
  - kind: header_present
    name: X-Test
references:
  - https://example.com
tags: []
`
	_, err := ParseDocuments([]byte(doc))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_similarityMinTooLow_forSafe(t *testing.T) {
	const doc = `
id: sim.low
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
    from: a
    to: b
matchers:
  - kind: response_body_similarity
    min_score: 0.5
references:
  - https://example.com
tags: []
`
	_, err := ParseDocuments([]byte(doc))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_fullMode_allowsMultipleMutations(t *testing.T) {
	const doc = `
id: full.multi
name: n
category: c
severity: high
confidence: high
safety:
  mode: full
  destructive: true
target:
  methods: [GET]
  where: path
prerequisites: []
mutations:
  - kind: rotate_request_headers
    headers:
      - name: Z
        value: "1"
  - kind: path_normalization_variant
    style: trailing_slash
matchers:
  - kind: status_code_unchanged
references:
  - https://example.com
tags: []
`
	rules, err := ParseDocuments([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || len(rules[0].Mutations) != 2 {
		t.Fatalf("%+v", rules)
	}
}
