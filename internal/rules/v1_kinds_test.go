package rules

import "testing"

func TestV1MutationsAndMatchers_roundTripYAML(t *testing.T) {
	const doc = `
id: v1.coverage
name: V1 kind coverage
category: test
severity: low
confidence: high
safety:
  mode: safe
  destructive: false
target:
  methods: [GET, POST]
  where: path
prerequisites: []
mutations:
  - kind: replace_path_param
    param: id
    from: self
    to: other
  - kind: merge_json_fields
    fields:
      role: admin
  - kind: path_normalization_variant
    style: double_slash
  - kind: rotate_request_headers
    headers:
      - name: X-Forwarded-For
        value: 127.0.0.2
matchers:
  - kind: status_code_unchanged
  - kind: response_body_similarity
    min_score: 0.9
  - kind: json_path_absent
    path: $.error
  - kind: status_in
    allowed: [200, 204]
  - kind: header_present
    name: X-RateLimit-Remaining
  - kind: header_absent
    name: Retry-After
  - kind: status_differs_from_baseline
  - kind: response_body_substring
    substring: needle
  - kind: json_path_equals
    path: field
    value: v
  - kind: response_header_differs_from_baseline
    name: ETag
references:
  - https://example.com
tags: [v1]
`
	rules, err := ParseDocuments([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatal(rules)
	}
	if len(rules[0].Mutations) != 4 || len(rules[0].Matchers) != 10 {
		t.Fatalf("mutations %d matchers %d", len(rules[0].Mutations), len(rules[0].Matchers))
	}
}
