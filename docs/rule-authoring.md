# Rule authoring

Rules are YAML documents. Each file may contain multiple documents. Loading walks `AXIOM_RULES_DIR` for `*.yml` and `*.yaml`.

## Required top-level fields

| Field | Description |
| --- | --- |
| `id` | Stable identifier |
| `name` | Human title |
| `category` | Taxonomy bucket |
| `severity` | **Impact bucket** for findings: `info`, `low`, `medium`, `high`, or `critical` only (feeds `findings.severity` and evidence JSON; **not** the assessment tier and **not** `confidence`) |
| `confidence` | Declared signal quality: **`high`**, **`medium`**, or **`low`** only (stored on the rule; `low` caps findings at **tentative**) |
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

## V1 safe and passive semantics (current supported families)

Supported planner families remain: **IDOR** (path or query swap), **mass assignment** (JSON merge), **path normalization** variants, **rate-limit / abuse** header rotation.

When `safety.mode` is **`safe`** or **`passive`**:

- **Exactly one mutation** per rule. Model each check as its own rule document (multi-document YAML files are fine). `full` mode may still list multiple mutations for advanced packs.
- Matchers must not contradict each other (for example do not combine `status_code_unchanged` with `status_differs_from_baseline`).
- **Family-specific matcher allowlists:** IDOR, mass assignment, and path normalization rules may use body or status-oriented matchers only (`header_present`, `header_absent`, and `response_header_differs_from_baseline` are rejected there). **Rate-limit header** rules must include at least one header-oriented matcher among those three plus may combine status/body matchers.
- **`response_body_similarity.min_score`** must be **>= 0.75** on safe/passive rules. Similarity below **0.9** still counts as a **weak signal** at finding time (findings stay **tentative** even when matchers pass).

## Finding fields vs rule YAML

When matchers pass with complete HTTP evidence, the service persists:

- **`severity`** on the finding is the rule’s impact bucket (unchanged semantics).
- **`rule_declared_confidence`** on the finding is the YAML `confidence` field (`high`/`medium`/`low`) only—it is **not** the assessment tier.
- **`assessment_tier`** on the finding is **`confirmed`**, **`tentative`**, or **`incomplete`** (no ML). **`incomplete`** applies when baseline or mutated execution ids are missing, either side has HTTP status `0`, or the diff summary is empty. **`tentative`** applies when the rule declared `low` confidence, severity is `info` or `low`, or a weak matcher signal is configured. Weak-signal **`assessment_notes`** today: **`weak_body_substring_matcher`**; or **`weak_body_similarity_matcher`** plus **`similarity_min_score_<x>`** when **`response_body_similarity.min_score` < 0.9** (the **`confirmed`** threshold for that matcher is **0.9**).
- **`evidence_summary`** (JSON, `schema_version` **1**): `rule_id`, baseline and mutated execution ids, endpoint method/path template, `matcher_outcomes` (index, kind, pass, short `summary`), `diff_points`, **`assessment_tier`** (post-run sufficiency snapshot, same as the column), **`rule_severity`** and **`impact_severity`** (same impact bucket as YAML `severity` / finding `severity`—both keys are written for readability; legacy rows may have only `rule_severity`), **`rule_declared_confidence`** (same as column), optional `assessment_notes`, optional **`interpretation_hints`** (stable scanner-policy strings that gloss **why the tier is not confirmed**—orthogonal to `assessment_notes`, which record weak-signal causes). **`assessment_tier`** is **not** a substitute for **`confidence`**; **`rule_severity` / `impact_severity`** are **not** confidence or tier.
- **`summary`** (column, list + detail): same base sentence as today (`rule … matched for …`); if tier is not **`confirmed`** and **`assessment_notes`** is non-empty, the runner appends **`; assessment: <codes>`** (comma-joined, same order as persisted notes), then optional **`; interpretation: <codes>`** when **`interpretation_hints`** is non-empty, so list rows stay aligned with **`evidence_summary`** without re-parsing JSON.

Rule validation failures are returned as numbered multi-line messages (for example from `GET /v1/rules`) with bracketed categories such as `[metadata]`, `[v1 safe/passive]`, `[matchers]`.

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
| `status_differs_from_baseline` | none |
| `response_body_similarity` | `min_score` (0 through 1 inclusive; >= 0.75 on safe/passive) |
| `response_body_substring` | `substring` (non-empty) |
| `json_path_absent` | `path` (non-empty) |
| `json_path_equals` | `path`, `value` |
| `status_in` | `allowed` (non-empty array of integer HTTP status codes) |
| `header_present` | `name` (non-empty) |
| `header_absent` | `name` (non-empty) |
| `response_header_differs_from_baseline` | `name` (non-empty) |

## Example: IDOR path swap

See `rules/builtin/idor_path_swap.example.yaml`. Other production-shaped examples: `mass_assignment_privilege.example.yaml`, `path_normalization_bypass.example.yaml`, `rate_limit_header_rotation.example.yaml`.

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
