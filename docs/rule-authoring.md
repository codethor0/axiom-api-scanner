# Rule authoring

Rules are YAML documents. Each file may contain multiple documents. Loading walks `AXIOM_RULES_DIR` for `*.yml` and `*.yaml`.

## Required top-level fields

| Field | Description |
| --- | --- |
| `id` | Stable identifier |
| `name` | Human title |
| `category` | Taxonomy bucket |
| `severity` | Reported severity |
| `confidence` | Expected signal quality |
| `safety.mode` | `passive`, `safe`, or `full` |
| `safety.destructive` | Boolean |
| `target.methods` | HTTP methods |
| `target.where` | Selector for where the rule applies |
| `prerequisites` | List (may be empty) |
| `mutations` | Non-empty list of typed mutations |
| `matchers` | Non-empty list of typed matchers |
| `references` | Non-empty citations |
| `tags` | Labels |

Unknown `kind` values in mutations or matchers fail validation at load time.

## V1 mutation kinds

| `kind` | Required fields |
| --- | --- |
| `replace_path_param` | `param`, `from`, `to` (non-empty strings) |
| `replace_query_param` | `param`, `from`, `to` |
| `merge_json_fields` | `fields` (non-empty object) |
| `path_normalization_variant` | `style` one of: `trailing_slash`, `double_slash`, `dot_segment`, `case_variant`, `encoded_slash` |
| `rotate_request_headers` | `headers` (non-empty array of `{ name, value }`) |

## V1 matcher kinds

| `kind` | Required fields |
| --- | --- |
| `status_code_unchanged` | none |
| `response_body_similarity` | `min_score` (0 through 1 inclusive) |
| `json_path_absent` | `path` (non-empty) |
| `status_in` | `allowed` (non-empty array of integer HTTP status codes) |
| `header_present` | `name` (non-empty) |
| `header_absent` | `name` (non-empty) |

## Example: IDOR path swap

See `rules/builtin/idor_path_swap.example.yaml`.

## Example: passive probe with query swap

```yaml
id: axiom.example.query_swap
name: Example query IDOR probe
category: broken_object_level_authorization
severity: medium
confidence: low
safety:
  mode: passive
  destructive: false
target:
  methods: [GET]
  where: query.id
prerequisites: []
mutations:
  - kind: replace_query_param
    param: id
    from: self
    to: foreign
matchers:
  - kind: status_code_unchanged
references:
  - https://owasp.org/www-project-api-security/
tags:
  - example
```

## API projection

`GET /v1/rules` returns JSON where each mutation and matcher is flattened: a `kind` field plus kind-specific keys (for example `param`, `from`, `to`).
