# HTTP API (control plane)

Base path: `/v1`

All successful JSON responses use explicit structs. Errors use this envelope:

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "Human explanation"
  }
}
```

## Scans

### POST /v1/scans

Creates a persisted scan in `queued` status.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `target_label` | string | yes | Non-empty, max 256 characters |
| `safety_mode` | string | yes | One of `passive`, `safe`, `full` |
| `allow_full_execution` | boolean | yes | Must be `true` when `safety_mode` is `full` |
| `base_url` | string | no | Absolute URL validated when present |
| `auth_headers` | object | no | Map of header name to value applied on baseline and mutation requests |

`full` mode remains opt-in (`full_mode_requires_opt_in` when misconfigured).

Response: `201` with `Scan` including `run_phase`, optional `run_error`, `base_url`, `auth_headers`, baseline progress fields (`baseline_run_status`, `baseline_run_error`, `baseline_endpoints_total`, `baseline_endpoints_done`), mutation progress (`mutation_run_status`, `mutation_run_error`, `mutation_candidates_total`, `mutation_candidates_done`), and `findings_count`.

### PATCH /v1/scans/{scanID}

Updates target configuration without touching lifecycle `status`. JSON fields:

- `base_url` (optional string): replaces the stored base URL when provided.
- `auth_headers` (optional object): used only when `replace_auth_headers` is true; replaces headers.
- `replace_auth_headers` (boolean, default false).

### GET /v1/scans/{scanID}

Returns a scan by UUID. `404` when absent.

### POST /v1/scans/{scanID}/control

Transitions scan lifecycle state only (`start`, `pause`, `cancel`). Baseline execution uses a separate route so lifecycle rules stay honest.

### GET /v1/scans/{scanID}/run/status

Operator read model for orchestration. Returns `200` with one JSON object. **Canonical** groups (use these for new integrations):

| Group | Role |
| --- | --- |
| `scan` | Lifecycle `status`, `target_label`, `safety_mode`, `id` (no credentials). |
| `run` | `phase` (persisted `run_phase`); `orchestrator_error` (pipeline stop reason **only** when `phase` is `failed`, from `run_error`); `baseline_run_status`, `baseline_run_error` (sub-run message **only** when baseline status is `failed`); `mutation_run_status`, `mutation_run_error` (sub-run message **only** when mutation status is `failed`). |
| `progress` | Counters from the scan row plus `endpoints_discovered` from imported endpoint count (no percentages or estimates). Same numbers as `summary` for baseline/mutation totals where both exist; `progress` is unchanged for older readers. |
| `summary` | Operator read model: `endpoints_imported` (imported endpoint row count); `baseline` / `mutation` each with `run_status`, `total`, `completed`, `skipped` from **persisted scan columns only** (`skipped` is `max(0, total-completed)` when that runner’s status is `succeeded`, else `0`); `findings_created` mirrors `findings_count` on the scan row. |
| `findings_summary` | **Read-only** aggregates over stored `findings` rows for this scan: `total`, `by_assessment_tier`, `by_severity` (maps omit empty buckets). The handler loads **SQL aggregates** (`COUNT` / `GROUP BY`), not full finding rows—**wire JSON is unchanged** from listing-and-bucketing semantics. No new filters or endpoints. |
| `rule_family_coverage` | **Factual** signals for four stable V1 mutation families (whether **mutated** `execution_records` exist for rules of that family, joined with rules loaded from `AXIOM_RULES_DIR`). The handler reads **narrow execution tallies** (`scan_endpoint_id`, `phase`, `rule_id`, `response_status`) for the scan, not full exchange bodies. See **Rule family coverage** below. |
| `guidance` | Action-oriented `next_steps` array (`code` + `detail`); **always present** (may be empty). Distinct from `diagnostics` (state/skips/blocks/consistency, not prescriptive actions). |
| `coverage` | Auth/security hints (no secrets). |
| `protected_route_coverage` | **Persisted-facts only:** splits imported `scan_endpoints` rows and `execution_records` (baseline + mutated) by whether the **OpenAPI import** attached `security_scheme_hints` to the operation. Counts HTTP status buckets (**401**, **403**, **2xx**) for baseline rows on declared-secure operations only. Does **not** prove token validity, session freshness, or role coverage—only what was stored. When **`executions_repository_configured`** is `false`, HTTP counts stay zero (no join performed). |
| `diagnostics` | `blocked_detail`, `skipped_detail`, and `consistency_detail` are **always JSON arrays** (possibly empty). Block/skip lines use grounded `code` + optional `detail`. `consistency_detail` surfaces **detected drift** between persisted columns and listing-derived read-model fields (the API does not repair storage). `phase_failed_next_step` and `resume_recommended` when `phase` is `failed`. |

**Stable wire shape (contract):** Successful `200` responses include these top-level keys in order: `scan`, `run`, `progress`, `summary`, `findings_summary`, `rule_family_coverage`, `guidance`, `coverage`, `protected_route_coverage`, `diagnostics`, `compatibility`. Nested **`guidance.next_steps`**, **`diagnostics.blocked_detail`**, **`diagnostics.skipped_detail`**, and **`diagnostics.consistency_detail`** are always arrays; **`protected_route_coverage`** exposes the field keys in contract tests (including zero-valued counters). Contract tests cover successful, public-only, blocked auth, failed, execution-repo-unavailable, and other scenarios.

**Protected vs public (operator meaning):** An imported operation is **declared secure** when its persisted row has non-empty `security_scheme_hints` (from OpenAPI). **Public-only** run status means `endpoints_declaring_security` is 0; the scanner may still hit targets that enforce auth outside the spec. **Declared-secure HTTP recorded** means at least one `execution_record` references a declared-secure `scan_endpoint_id` for baseline and/or mutated phase. The API does **not** classify “authenticated session verified”; it only reports configured `auth_headers`, stored requests, and stored response status codes.

**What the scanner cannot prove today:** Valid JWT/API-key semantics, refresh flows, RBAC across roles, or that 2xx on a declared-secure route implies correct authorization logic—only that a stored response had that status for one baseline exchange.

**Read-model invariants (expected relationships, not enforced by repair):**

- When a **`FindingRepository` is configured**, `summary.findings_created` (from `scans.findings_count`) should equal `findings_summary.total` (from the persisted findings **aggregate** query). If not, `diagnostics.consistency_detail` includes `findings_count_drift` citing both integers.
- **`baseline_endpoints_done`** must not exceed **`baseline_endpoints_total`** on the scan row; **`mutation_candidates_done`** must not exceed **`mutation_candidates_total`**. Violations emit `baseline_progress_inconsistent` or `mutation_progress_inconsistent` (or negative-counter variants).
- **`summary.*.skipped`** is never negative (it is derived as documented; if done exceeds total, skipped may hide the imbalance until the progress inconsistency diagnostic fires).
- When **`rule_family_coverage.unavailable` is absent**, each family’s `mutated_executions` must not exceed the count of `execution_records` with `phase=mutated` for the scan; the **sum** of the four family `mutated_executions` must not exceed that row count (if it does, `family_coverage_mutated_sum_exceeds_rows` documents the fact, including multi-family rules as a non-speculative explanation).

**Rule family coverage:** JSON keys: `idor_path_or_query_swap` (`replace_path_param` / `replace_query_param`), `mass_assignment_privilege_injection` (`merge_json_fields`), `path_normalization_bypass` (`path_normalization_variant`), `rate_limit_header_rotation` (`rotate_request_headers`). Each entry includes `exercised`, `rules_in_pack`, `mutated_executions`, optional `not_exercised_reason`, and optional **`not_exercised_contributors`** (extra grounded factors without duplicating the primary reason). Primary reasons remain: no rules for that family; mutation pass not succeeded; `mutation_candidates_total` is 0; or no mutated rows while the mutation pass succeeded with non-zero candidates. **Contributors (when not exercised) may include:** `no_eligible_imported_endpoints_for_family` (V1 planner marks every imported operation ineligible for rules in this family), and `declared_secure_openapi_operations_present_auth_headers_absent` when declared-secure operations exist on the import but the scan has no `auth_headers`. Top-level `unavailable` is set when the rules directory is not configured on the API instance, rules failed to load, or the execution repository is missing (per-entry mirrors in those cases).

**Guidance `next_steps` codes (may appear):** `import_openapi_first`, `configure_auth_headers`, `resume_after_baseline_failure`, `resume_after_mutation_failure`, `resume_orchestrated_run`, `no_eligible_mutation_candidates` — each only when the corresponding scan/endpoint/auth state is true; see unit tests for ordering and triggers.

**Compatibility (non-canonical):** only the `compatibility` object is legacy mirrored data. It duplicates `scan.id` -> `scan_id`, `run.phase` -> `phase`, `scan.status` -> `scan_status`, and `run.orchestrator_error` -> `last_error` for older clients. **`compatibility.last_error` is only the orchestrator failure** (same as `run.orchestrator_error`), not baseline/mutation sub-messages, so it does not overlap those fields. All other top-level groups are **canonical** for new integrations.

**Coverage unavailable:** `rule_family_coverage.unavailable` means family-level joins were not computed: missing `AXIOM_RULES_DIR` on the API process, rules directory load error, or no execution repository. Per-family stubs still appear with `rule_family_coverage_unavailable` / `rules_load_failed` style reasons; operators should fix configuration rather than interpret family zeros as “no traffic.” When **`protected_route_coverage.executions_repository_configured`** is `false`, HTTP record and status bucket counters stay zero; endpoint inventory fields on the same object still reflect imported `scan_endpoints` rows.

**Failure semantics:** When `phase` is `failed`, read `run.orchestrator_error` first. If baseline or mutation sub-status is `failed`, the corresponding `*_run_error` holds that runner’s message. When baseline status is **not** `failed`, `baseline_run_error` is omitted/empty in the response even if a stale string remains in storage (same for mutation). This keeps “current sub-run failure” unambiguous.

**Diagnostics codes (may appear; all factual):** `no_imported_endpoints`, `declared_security_without_auth`, `baseline_not_recorded`, `zero_mutation_candidates`; **route/auth visibility** in `skipped_detail`: `declared_secure_operations_not_in_baseline_runner_scope`, `declared_secure_baseline_scope_without_recorded_baseline_http`, `declared_secure_baseline_responses_only_401_or_403`, `declared_secure_baseline_without_auth_headers_only_401_or_403`, `mutation_http_not_recorded_for_declared_secure_endpoints`, `mutated_http_only_recorded_for_declared_secure_endpoints`; and **consistency** codes `findings_count_drift`, `baseline_progress_inconsistent`, `mutation_progress_inconsistent`, `scan_row_negative_baseline_counter`, `scan_row_negative_mutation_counter`, `family_coverage_mutated_sum_exceeds_rows`, `family_coverage_mutated_exceeds_rows` — see unit tests for exact trigger conditions. No speculative causes are invented. **`diagnostics` and `guidance` are complementary:** diagnostics report state, blocks, skips, consistency, and execution-vs-import facts; `guidance.next_steps` lists follow-up actions when grounded.

**Phase semantics:** Exactly one `run_phase` at a time. Values: `planned`, `baseline_running`, `baseline_complete`, `mutation_running`, `mutation_complete`, `findings_complete`, `failed`, `canceled`. Illegal transitions return `409` from `POST .../run`. Per-endpoint baseline skip reasons remain on **`POST .../executions/baseline`** `result.skipped_detail`, not in this status object.

### POST /v1/scans/{scanID}/run

**Canonical V1 sync orchestration route.** Same path for `start`, `resume`, and `cancel`; no duplicate “run” endpoints. Runs the pipeline **in the HTTP request thread** (no queue, no background scheduler).

Request body:

```json
{ "action": "start" | "resume" | "cancel", "force_rerun_baseline": false }
```

- `start`: normal forward run (scan may be auto-started from `queued`). `run_phase` `failed` does **not** advance without `resume`.
- `resume`: **retry after `failed`**. Before work resumes, if baseline already succeeded (`baseline_run_status`, totals, and done counts on the scan row show a complete successful pass), orchestration reconciles `run_phase` to `baseline_complete` so operators are not shown `baseline_running` for work that is already done. Baseline HTTP is **not** rerun unless `force_rerun_baseline` is `true`. Mutation work continues from persisted candidates: existing `(scan, endpoint, rule, candidate_key)` mutated rows are reused; findings use a unique evidence tuple and do not duplicate on resume.
- `cancel`: sets lifecycle cancel when allowed and persists `run_phase` `canceled`. Does **not** require `Orchestrator` to be configured; `Scans` + `ScanRun` are enough.
- `force_rerun_baseline`: when `true`, allows transition from `baseline_complete` back to `baseline_running` and re-executes baseline HTTP (explicit opt-in).

**Resume does not guarantee:** replays of unrelated historical partial state beyond what is stored in `execution_records` and scan counters; correctness of the target if it changed between attempts; completion if rules or imported endpoints change mid-flight (determinism is per persisted work list and store state at resume time).

**Sync-only meaning:** `start` and `resume` block until the orchestrator finishes, fails, or the request context is canceled. Use `GET .../run/status` to read persisted phase and counters without driving work.

Successful responses return **`200`** with the same JSON shape as `GET .../run/status` (after `start` or `resume` complete synchronously). Errors:

- `503` `service_unavailable` when `start`/`resume` is requested but orchestration is not wired (`Orchestrator` nil in `cmd/api`).
- `409` `invalid_run_phase` when a phase transition is rejected (wrapped `invalid scan run phase`).
- `404` when the scan does not exist.

The granular routes `POST .../executions/baseline` and `POST .../executions/mutations` remain available; orchestration composes them internally.

### POST /v1/scans/{scanID}/specs/openapi

Body: raw OpenAPI 3.x YAML or JSON (same limits as global validate). Persists endpoints for this scan (full replace). Before validation, the importer **clears schema and parameter `example` fields** so published specs with non-strict examples (for example string literals for numeric types) can still be imported; examples are not used for endpoint discovery. Response:

```json
{
  "scan_id": "uuid",
  "endpoints": [ { "method": "GET", "path": "/...", ... } ],
  "count": 1
}
```

### GET /v1/scans/{scanID}/endpoints

Returns **`200`** with a JSON object: **`items`** (array of **endpoint read** objects), same stable envelope pattern as execution/finding lists.

**Endpoint read** fields:

| Field | Meaning |
| --- | --- |
| `id`, `scan_id` | Stable UUID for the imported row; scan scope. |
| `method`, `path_template`, `operation_id` | From OpenAPI import (`operation_id` omitted when empty). |
| `security_scheme_hints` | Names of OpenAPI security schemes attached at import (may be empty). |
| `declares_openapi_security` | `true` iff `security_scheme_hints` is non-empty on the persisted row (derived read-only flag for filtering/sorting mentally). |
| `request_content_types`, `response_content_types`, `request_body_json`, `created_at` | As stored on `scan_endpoints`. |
| `summary` | Present unless `include_summary=false`. Counts are **only** persisted fact: numbers of `execution_records` with `phase=baseline` / `phase=mutated` and of `findings` rows with this `scan_endpoint_id`. Not “attempted” beyond stored rows; skipped baseline work leaves no execution row. |

**Query parameters (read-only, optional):**

| Parameter | Meaning |
| --- | --- |
| `method` | Case-insensitive match on stored HTTP method (e.g. `GET`). |
| `declares_security` | `true` or `false`: filter by non-empty vs empty `security_scheme_hints`. |
| `include_summary` | `true` (default) or `false`: omit `summary` objects and skip aggregate joins for a lighter inventory read. |

Invalid `include_summary` or `declares_security` values return **`400`** `invalid_query`.

Ordering is deterministic: `path_template` ascending, then `method` ascending (unchanged from storage).

### POST /v1/scans/{scanID}/executions/baseline

Runs one sequential baseline pass: GET and JSON POST operations only, against `base_url`, using imported path templates with placeholder substitution. Persists `execution_records` and updates baseline counters on the scan. Response `200` with:

- `result`: machine-readable runner output (`status`, counts, record ids, skips, warnings)
- `plan_by_endpoint`: planner decisions per imported endpoint (from rules in `AXIOM_RULES_DIR`)
- `mutation_candidates`: capped list of deterministic candidates from eligible rules

Failure to run (for example missing `base_url` or endpoints) yields `result.status` of `failed` and an `error` string inside `result`; the HTTP status remains `200` unless persistence itself errors.

### POST /v1/scans/{scanID}/executions/mutations

Runs one sequential mutation pass for all eligible V1 work items derived from imported endpoints and rules in `AXIOM_RULES_DIR`. Requires a successful prior baseline on the scan (`baseline_run_status` must be `succeeded`). Uses GET and JSON POST only; enforces the same URL scope rules as baseline; stores phase `mutated` execution rows; evaluates matchers against the latest baseline per endpoint; creates findings only when diff evaluation completes without `incomplete`. Response `200` with:

```json
{
  "result": {
    "status": "succeeded",
    "candidates_total": 0,
    "candidates_executed": 0,
    "candidates_skipped": 0,
    "mutated_execution_ids": [],
    "finding_ids": [],
    "warnings": []
  }
}
```

If baseline is missing or not `succeeded`, `result.status` is `failed` with `baseline_must_succeed_first`.

### GET /v1/scans/{scanID}/executions

Lists stored HTTP exchanges for the scan. **Response shape (breaking vs historical raw-array clients):** JSON object with **`items`** (array of **execution read** objects) and **`meta`** (pagination).

**Execution read** fields:

| Field | Meaning |
| --- | --- |
| `id`, `scan_id`, `scan_endpoint_id`, `created_at`, `duration_ms` | Identity and timing. |
| `phase` | `baseline` or `mutated` (persisted execution phase). |
| `execution_kind` | Same value as `phase`; use either for filtering mentally; both are always set together. |
| `mutation_rule_id` | Rule id for mutated rows (empty for baseline). |
| `candidate_key` | Mutation work-item key for **mutated** rows only (resume/dedup); empty for baseline. |
| `request`, `response` | Full redacted snapshots (`request.url`, `request.body`, header maps, `response.status_code`, `response.body`, etc.). |
| `request_summary` | Concise view: `method`, `url_short` (length-capped from stored URL), `header_count`, `body_byte_length` (same redacted body as `request.body`). |
| `response_summary` | Concise view: `status_code`, `content_type`, `header_count`, `body_byte_length` (same body as `response.body`). |

**Pagination (keyset cursor):** `meta.limit` echoes the applied page size (default **50**, maximum **200**). `meta.has_more` is true when more rows exist. `meta.next_cursor` is an opaque string: pass it as **`cursor`** on the next request (with the **same** `sort`, `order`, and narrow filters) to continue. Ordering is deterministic: primary sort key, then `created_at`, then row `id`. Cursors are validated against `sort` and `order`; a mismatched cursor returns `400` `invalid_cursor`.

**Supported `sort` (executions):** `created_at` (default), `phase` (baseline before mutated for `asc`, reversed for `desc`). Other values return `400` `invalid_sort`.

**Supported `order`:** `asc` (default), `desc`. Invalid values return `400` `invalid_order`.

**Not supported:** `offset` (returns `400` `unsupported_query_parameter`); use `cursor` only.

Filters (unchanged, combined with AND): `phase`, `execution_kind` (alias; must match `phase` if both set, else `400` `invalid_filter`), `scan_endpoint_id`, `rule_id`, `response_status`.

### GET /v1/scans/{scanID}/executions/{executionID}

Returns one execution read object (same shape as **`items[]`** elements) when it belongs to the scan. `404` when missing or mismatched.

### GET /v1/scans/{scanID}/findings

Lists findings for the scan. **Response shape:** object with **`items`** (**finding read** array) and **`meta`** (same pagination fields as executions).

Rows are produced only after a mutation pass when matchers pass with complete diff evaluation. Each **finding read** includes all stored columns (`id`, `scan_id`, `rule_id`, `category`, `severity`, `rule_declared_confidence`, `assessment_tier`, `summary`, `evidence_summary`, `evidence_uri`, `scan_endpoint_id`, `baseline_execution_id`, `mutated_execution_id`, `created_at`) plus optional **`evidence_inspection`** when there is something to show (see `GET /v1/findings/{findingID}`).

**Pagination:** Same cursor model as executions (`limit` default 50, max 200; `cursor` + `meta.next_cursor`). Deterministic tie-break: after primary sort, `created_at`, then `id`.

**Supported `sort` (findings):** `created_at` (default), `severity` (order: info, low, medium, high, critical for `asc`).

**Supported `order`:** `asc` (default), `desc`.

**Not supported:** `offset` (`400` `unsupported_query_parameter`). Unsupported `sort` for this resource (e.g. `phase`) returns `400` `invalid_sort`.

**Non-overlapping semantics:** `severity` is impact; `assessment_tier` is post-run confidence in the signal; `rule_declared_confidence` is YAML authoring quality.

Optional **filter** query parameters (all exact match, ANDed with pagination): `assessment_tier`, `severity`, `rule_declared_confidence`, `rule_id`.

## Findings

### GET /v1/findings/{findingID}

Returns one **finding read** object (same JSON shape as list elements), including `evidence_inspection` when applicable.

Rule load failures (`GET /v1/rules`) return `rule_load_failed` with a **numbered, multi-line** validation message when YAML fails validation.

### GET /v1/findings/{findingID}/evidence

Returns finding-bound evidence from the legacy `evidence_artifacts` table (not the same as `execution_records`).

## Rules

### GET /v1/rules

Returns validated YAML rules from `AXIOM_RULES_DIR`.

## OpenAPI

### POST /v1/specs/openapi/validate

Validates OpenAPI and returns `{ "status": "valid" }`.

### POST /v1/specs/openapi/import

Returns `{ "endpoints": [ EndpointSpec ... ], "count": N }` without persisting to a scan.

## Verifying persistence

Postgres-backed behaviors (migrations through the latest version, `CreateFinding`, execution list, full endpoint replace) are exercised by `go test ./internal/storage/postgres/...` when `AXIOM_TEST_DATABASE_URL` is set. See [testing.md](testing.md) for the exact variables and a Docker example.

## Service configuration errors

Scan routes return `503` with `service_unavailable` when the backing repository is not wired. Baseline additionally requires `Baseline` runner configuration (production `cmd/api` sets this).
