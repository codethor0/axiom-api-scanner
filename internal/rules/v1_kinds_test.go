package rules

import "testing"

func TestV1SafeRules_oneMutationPerFamily_parse(t *testing.T) {
	const doc = `
id: axiom.v1.idor.smoke
name: IDOR smoke
category: test
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
  - kind: response_body_similarity
    min_score: 0.85
references:
  - https://owasp.org/API-Security/
tags: [v1]
---
id: axiom.v1.mass.smoke
name: mass assignment smoke
category: test
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
      role: admin
matchers:
  - kind: status_code_unchanged
  - kind: json_path_absent
    path: error
references:
  - https://owasp.org/API-Security/
tags: [v1]
---
id: axiom.v1.pathnorm.smoke
name: path normalization smoke
category: test
severity: medium
confidence: medium
safety:
  mode: safe
  destructive: false
target:
  methods: [GET]
  where: path
prerequisites: []
mutations:
  - kind: path_normalization_variant
    style: double_slash
matchers:
  - kind: status_code_unchanged
references:
  - https://owasp.org/API-Security/
tags: [v1]
---
id: axiom.v1.ratelimit.smoke
name: rate limit header smoke
category: test
severity: medium
confidence: medium
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
        value: 127.0.0.2
matchers:
  - kind: status_code_unchanged
  - kind: response_header_differs_from_baseline
    name: X-RateLimit-Remaining
references:
  - https://owasp.org/API-Security/
tags: [v1]
`
	rules, err := ParseDocuments([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("want 4 rules got %d", len(rules))
	}
	for _, r := range rules {
		if len(r.Mutations) != 1 {
			t.Fatalf("rule %s mutations %d", r.ID, len(r.Mutations))
		}
	}
}
