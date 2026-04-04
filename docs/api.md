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

## Resource responsibilities (V1 read paths)

| Resource | Role | Typical navigation |
| --- | --- | --- |
| **Scan** (`GET /v1/scans/{id}`) | Lifecycle, `target_label`, `safety_mode`, progress columns, `findings_count`; not orchestration diagnostics. | Entry point after create; use **`run/status`** for phase and guidance. |
| **Scan run status** (`GET .../run/status`) | Orchestration read model: `run.phase`, progress/summary mirrors, aggregates, diagnostics, **`drilldown`** path hints. | Jump to inventory, execution/finding lists, or **scan detail** via `drilldown.scan_detail_path`. |
| **Endpoint inventory / detail** | Imported OpenAPI operations per scan; detail adds **`investigation`** + **`drilldown`** (filtered list query fragments). | From run status or scan drilldown to inventory; from endpoint detail to filtered executions/findings and back to **run status** via `drilldown.run_status_path`. |
| **Executions** (list / GET by id) | Stored HTTP exchanges; list is summary-only; detail is full redacted request/response. | From drilldown paths or endpoint filters; use execution id from list or finding linkage for GET detail. |
| **Findings** (list / GET by id / evidence) | Assessment output; list is triage-only; detail includes **`evidence_summary`**; evidence route returns artifact bodies. The persisted **`summary`** string matches the mutation runner: non-**`confirmed`** tiers with **`assessment_notes`** append **`; assessment: <comma-joined codes>`** (same values as **`evidence_summary.assessment_notes`**), then optional **`; interpretation: <comma-joined codes>`** when **`evidence_summary.interpretation_hints`** is non-empty (stable tier-policy gloss, not target-specific fixture labels). Weak body matchers emit explicit assessment tokens (e.g. **`weak_body_similarity_matcher`** plus **`similarity_min_score_<value>`** when **`response_body_similarity.min_score` < 0.9**, or **`weak_body_substring_matcher`** for substring matchers). **`confirmed`** findings use the base **`summary`** only; **`interpretation_hints`** is omitted/empty. **No-finding** for a rule is absence of a row after a completed mutation pass (e.g. matchers did not pass); it is not encoded in **`interpretation_hints`**. | From scan or endpoint-filtered finding list; follow **`evidence_uri`** and ids from list rows to detail. |

Duplicate numbers between **`summary`**, **`progress`**, and **`findings_summary`** are intentional mirrors for the same persisted facts (see run status invariants), not alternate estimators.

**Repeatable local validation:** `make e2e-local` (see [testing.md](testing.md#local-docker-end-to-end-v1)) drives a fixed **httpbin** + Postgres stack, exercises import, inventory, ad-hoc baseline/mutation POSTs, **`GET .../run/status`** (including **`run.progression_source`** and **`run.findings_recording_status`** assertions), endpoint detail drilldown, execution list/detail, findings list/detail + evidence, filtered findings, then a second scan using **`POST .../run`**. After ad-hoc runner POSTs, **`run.phase`** may remain **`planned`** while **`run.progression_source`** is **`adhoc`** and baseline/mutation sub-status fields show **`succeeded`**; orchestration via **`POST .../run`** sets **`run.progression_source`** to **`orchestrator`** and aligns **`run.phase`** with **`findings_complete`** when the pipeline finishes. **`make benchmark-findings-local`** (see [testing.md](testing.md#finding-quality-benchmark-local-httpbin-and-nginx-rate-stub)) runs **two** ad-hoc scans: httpbin (including **no-finding** rate-limit on that target) and a tiny **local nginx** stub (**`127.0.0.1:18081`**) that yields a **confirmed** rate-limit finding plus an extra **tentative** path-normalization row; it asserts read paths and **`rule_family_coverage`** for the stub scan. **HTTP responses do not include `bench_*` harness codes**—those come from the benchmark helper (**`go run ./scripts/benchharness`**) and separate **`interpretation_hints`** on each finding (scanner policy only).

**Harness vs API:** Use **`assessment_notes`**, **`interpretation_hints`**, and **`summary`** on **`GET /v1/findings/{id}`** for every scan. Use **`bench_*`** strings only when interpreting the **documented local benchmark** (`target_label` **`bench-httpbin-v1-families`** or **`bench-rate-stub`**) so operators can separate **scanner policy** from **fixture layout** without storing target-specific labels on finding rows.

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
| `run` | `phase` (persisted `run_phase`); `orchestrator_error` (pipeline stop reason **only** when `phase` is `failed`, from `run_error`); `baseline_run_status`, `baseline_run_error` (sub-run message **only** when baseline status is `failed`); `mutation_run_status`, `mutation_run_error` (sub-run message **only** when mutation status is `failed`); **`progression_source`** (`orchestrator` \| `adhoc` \| `idle`, derived from persisted phase + runner fields—see **Run progression** below); **`findings_recording_status`** (`mutation_not_run` \| `mutation_in_progress` \| `mutation_failed` \| `complete`, derived from `mutation_run_status` only: **`complete`** means the mutation pass finished successfully and the finding pipeline ran, including **zero** findings). |
| `progress` | Counters from the scan row plus `endpoints_discovered` from imported endpoint count (no percentages or estimates). Same numbers as `summary` for baseline/mutation totals where both exist; `progress` is unchanged for older readers. |
| `summary` | Operator read model: `endpoints_imported` (same integer as **`progress.endpoints_discovered`**—imported `scan_endpoints` count); `baseline` / `mutation` each with `run_status`, `total`, `completed`, `skipped` from **persisted scan columns only** (`skipped` is `max(0, total-completed)` when that runner’s status is `succeeded`, else `0`); `findings_created` (same integer as **`progress.findings_created`** / **`scans.findings_count`**, not recomputed from listing findings). |
| `findings_summary` | **Read-only** aggregates over stored `findings` rows for this scan: `total`, `by_assessment_tier`, `by_severity` (maps omit empty buckets). The handler loads **SQL aggregates** only (one round-trip to PostgreSQL: total plus tier/severity bucket JSON), not full finding rows—**wire JSON is unchanged** from listing-and-bucketing semantics. No new filters or endpoints. |
| `rule_family_coverage` | **Factual** signals for four stable V1 mutation families (whether **mutated** `execution_records` exist for rules of that family, joined with rules loaded from `AXIOM_RULES_DIR`). The handler reads **narrow execution tallies** (`scan_endpoint_id`, `phase`, `rule_id`, `response_status`) for the scan, not full exchange bodies. See **Rule family coverage** below. |
| `guidance` | Action-oriented `next_steps` array (`code` + `detail`); **always present** (may be empty). Distinct from `diagnostics` (state/skips/blocks/consistency, not prescriptive actions). |
| `coverage` | Auth/security hints (no secrets). |
| `protected_route_coverage` | **Persisted-facts only:** splits imported `scan_endpoints` rows and `execution_records` (baseline + mutated) by whether the **OpenAPI import** attached `security_scheme_hints` to the operation. Counts HTTP status buckets (**401**, **403**, **2xx**) for baseline rows on declared-secure operations only. Does **not** prove token validity, session freshness, or role coverage—only what was stored. When **`executions_repository_configured`** is `false`, HTTP counts stay zero (no join performed). |
| `diagnostics` | `blocked_detail`, `skipped_detail`, and `consistency_detail` are **always JSON arrays** (possibly empty). Each line is `code`, optional `detail`, and optional **`category`**: **`blocked`** (import/auth precondition), **`auth_limit`** (credential gap or auth-shaped HTTP pattern; may appear in `blocked_detail` or `skipped_detail`), **`skipped`** (recorded state or coverage gap without implying storage corruption), **`inconsistent`** (only in `consistency_detail`: counters or joins disagree). **Guidance** lines do not use `category`. `phase_failed_next_step` and `resume_recommended` when `phase` is `failed`. |
| `drilldown` | **Path-only** navigation hints (leading `/v1/...`, no scheme or host): `scan_id`, **`scan_detail_path`** (`GET /v1/scans/{id}` for lifecycle/config, distinct from this run-status URL), `endpoints_inventory_path`, `executions_list_path`, `findings_list_path`, `run_status_path` (this resource). Values are **derived from the request scan id** so operators can navigate without embedding list payloads. Same object appears on successful **`POST .../run`** responses (same shape as this `GET`). |

**Implementation note (performance, not wire):** For `progress` / `coverage` / `rule_family_coverage` / `protected_route_coverage`, the handler loads **`scan_endpoints`** rows needed for **V1 planner eligibility** and **declared-security** classification only (`ListScanEndpointsForRunStatus`): identity, method, path template, security hints, JSON-body flag, timestamps. It does **not** load request/response content-type columns used by **`GET .../endpoints`** inventory. Full endpoint rows are still used for OpenAPI import responses, inventory lists, and runners.

**Stable wire shape (contract):** Successful `200` responses include these top-level keys in order: `scan`, `run`, `progress`, `summary`, `findings_summary`, `rule_family_coverage`, `guidance`, `coverage`, `protected_route_coverage`, `diagnostics`, `drilldown`, `compatibility`. Nested **`guidance.next_steps`**, **`diagnostics.blocked_detail`**, **`diagnostics.skipped_detail`**, and **`diagnostics.consistency_detail`** are always arrays; **`drilldown`** exposes **`scan_id`**, **`scan_detail_path`**, inventory and list paths, and **`run_status_path`** in contract tests; **`protected_route_coverage`** exposes the field keys in contract tests (including zero-valued counters). Contract tests cover successful, public-only, blocked auth, failed, execution-repo-unavailable, and other scenarios.

**Protected vs public (operator meaning):** An imported operation is **declared secure** when its persisted row has non-empty `security_scheme_hints` (from OpenAPI). **Public-only** run status means `endpoints_declaring_security` is 0; the scanner may still hit targets that enforce auth outside the spec. **Declared-secure HTTP recorded** means at least one `execution_record` references a declared-secure `scan_endpoint_id` for baseline and/or mutated phase. The API does **not** classify “authenticated session verified”; it only reports configured `auth_headers`, stored requests, and stored response status codes.

**What the scanner cannot prove today:** Valid JWT/API-key semantics, refresh flows, RBAC across roles, or that 2xx on a declared-secure route implies correct authorization logic—only that a stored response had that status for one baseline exchange.

**Read-model invariants (expected relationships, not enforced by repair):**

- **`progress.endpoints_discovered`** and **`summary.endpoints_imported`** are the same imported row count; **`progress.findings_created`** and **`summary.findings_created`** both mirror **`scans.findings_count`**. A mismatch between those pairs surfaces under `consistency_detail` (`read_model_endpoints_mismatch`, `read_model_findings_mismatch`).
- **`protected_route_coverage.endpoints_declaring_security` + `endpoints_without_security_declaration`** equals that imported count when tallies run on the same inventory; **`coverage.endpoints_declaring_security`** must match **`protected_route_coverage.endpoints_declaring_security`**. Mismatches → `protected_route_endpoint_buckets_mismatch`, `coverage_vs_protected_secure_count_mismatch`.
- When executions are configured, each **`phase=mutated`** row is counted in **`protected_route_coverage`** only if its `scan_endpoint_id` resolves to an imported endpoint; if more mutated rows exist than secure+public mutated buckets combined, **`mutated_executions_not_classified_in_protected_route`** records the gap (orphan foreign key or drift).
- When a **`FindingRepository` is configured**, `summary.findings_created` (from `scans.findings_count`) should equal `findings_summary.total` (from the persisted findings **aggregate** query). If not, `diagnostics.consistency_detail` includes `findings_count_drift` citing both integers.
- **`baseline_endpoints_done`** must not exceed **`baseline_endpoints_total`** on the scan row; **`mutation_candidates_done`** must not exceed **`mutation_candidates_total`**. Violations emit `baseline_progress_inconsistent` or `mutation_progress_inconsistent` (or negative-counter variants).
- **`summary.*.skipped`** is never negative (it is derived as documented; if done exceeds total, skipped may hide the imbalance until the progress inconsistency diagnostic fires).
- When **`rule_family_coverage.unavailable` is absent**, each family’s `mutated_executions` must not exceed the count of `execution_records` with `phase=mutated` for the scan; the **sum** of the four family `mutated_executions` must not exceed that row count (if it does, `family_coverage_mutated_sum_exceeds_rows` documents the fact, including multi-family rules as a non-speculative explanation).

**Rule family coverage:** JSON keys: `idor_path_or_query_swap` (`replace_path_param` / `replace_query_param`), `mass_assignment_privilege_injection` (`merge_json_fields`), `path_normalization_bypass` (`path_normalization_variant`), `rate_limit_header_rotation` (`rotate_request_headers`). Each entry includes `exercised`, `rules_in_pack`, `mutated_executions`, optional `not_exercised_reason`, and optional **`not_exercised_contributors`** (extra grounded factors without duplicating the primary reason). Primary reasons remain: no rules for that family; mutation pass not succeeded; `mutation_candidates_total` is 0; or no mutated rows while the mutation pass succeeded with non-zero candidates. **Contributors (when not exercised) may include:** `no_eligible_imported_endpoints_for_family` (V1 planner marks every imported operation ineligible for rules in this family), and `declared_secure_openapi_operations_present_auth_headers_absent` when declared-secure operations exist on the import but the scan has no `auth_headers`. Top-level `unavailable` is set when the rules directory is not configured on the API instance, rules failed to load, or the execution repository is missing (per-entry mirrors in those cases).

**Guidance `next_steps` codes (may appear):** `import_openapi_first`, `configure_auth_headers`, `resume_after_baseline_failure`, `resume_after_mutation_failure`, `resume_orchestrated_run`, `no_eligible_mutation_candidates` — each only when the corresponding scan/endpoint/auth state is true; see unit tests for ordering and triggers.

**Compatibility (non-canonical):** only the `compatibility` object is legacy mirrored data. It duplicates `scan.id` -> `scan_id`, `run.phase` -> `phase`, `scan.status` -> `scan_status`, and `run.orchestrator_error` -> `last_error` for older clients. **`compatibility.last_error` is only the orchestrator failure** (same as `run.orchestrator_error`), not baseline/mutation sub-messages, so it does not overlap those fields. All other top-level groups are **canonical** for new integrations.

**Coverage unavailable:** `rule_family_coverage.unavailable` means family-level joins were not computed: missing `AXIOM_RULES_DIR` on the API process, rules directory load error, or no execution repository. Per-family stubs still appear with `rule_family_coverage_unavailable` / `rules_load_failed` style reasons; operators should fix configuration rather than interpret family zeros as “no traffic.” When **`protected_route_coverage.executions_repository_configured`** is `false`, HTTP record and status bucket counters stay zero; endpoint inventory fields on the same object still reflect imported `scan_endpoints` rows.

**Failure semantics:** When `phase` is `failed`, read `run.orchestrator_error` first. If baseline or mutation sub-status is `failed`, the corresponding `*_run_error` holds that runner’s message. When baseline status is **not** `failed`, `baseline_run_error` is omitted/empty in the response even if a stale string remains in storage (same for mutation). This keeps “current sub-run failure” unambiguous.

**Diagnostics codes (may appear; all factual):** `no_imported_endpoints`, `declared_security_without_auth`, `baseline_not_recorded`, `zero_mutation_candidates`; **route/auth visibility** in `skipped_detail`: `declared_secure_operations_not_in_baseline_runner_scope`, `declared_secure_baseline_scope_without_recorded_baseline_http`, `declared_secure_baseline_responses_only_401_or_403`, `declared_secure_baseline_without_auth_headers_only_401_or_403`, `mutation_http_not_recorded_for_declared_secure_endpoints`, `mutated_http_only_recorded_for_declared_secure_endpoints`; **`consistency_detail` only:** `findings_count_drift`, `read_model_endpoints_mismatch`, `read_model_findings_mismatch`, `protected_route_endpoint_buckets_mismatch`, `coverage_vs_protected_secure_count_mismatch`, `mutated_executions_not_classified_in_protected_route`, `baseline_progress_inconsistent`, `mutation_progress_inconsistent`, `scan_row_negative_baseline_counter`, `scan_row_negative_mutation_counter`, `family_coverage_mutated_sum_exceeds_rows`, `family_coverage_mutated_exceeds_rows` — see unit tests for exact trigger conditions. No speculative causes are invented. **`diagnostics` and `guidance` are complementary:** diagnostics report state, blocks, skips, consistency, and execution-vs-import facts; `guidance.next_steps` lists follow-up actions when grounded.

**Run progression (machine-readable):** **`progression_source`** is **`orchestrator`** whenever persisted **`run_phase`** is not **`planned`** (orchestrator or cancel touched the row). It is **`adhoc`** when phase is still **`planned`** but **`baseline_run_status`**, **`mutation_run_status`**, or **`findings_count`** on the scan row shows work from **`POST .../executions/baseline`** / **`POST .../executions/mutations`**. It is **`idle`** when phase is **`planned`** and those signals are empty. Operators should use **`progression_source`** plus **`phase`** together: after ad-hoc runners, **`phase`** may stay **`planned`** while **`progression_source`** is **`adhoc`** and sub-status fields show completion.

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

Returns **`200`** with a JSON object: **`items`** (array of **endpoint read** objects) and **`meta`** (pagination), same stable envelope pattern as execution/finding lists.

**`meta` fields:** `limit` (requested page size, default 50, max 200), `sort`, `order` (`asc` or `desc`), `has_more`, optional `next_cursor` (opaque; pass as `cursor` for the next page).

**Pagination:** Keyset (**cursor**) only; **`offset` is rejected** with **`400`** `unsupported_query_parameter`. Cursors are valid only for the same `sort` and `order` as the request that produced them.

**Supported `sort` values (deterministic; UUID `id` tie-breaks when paths/methods/timestamps match):**

| `sort` | Ordering |
| --- | --- |
| `path` (default) | `path_template`, `method`, `id` |
| `method` | `method`, `path_template`, `id` |
| `created_at` | `created_at`, `id` |

Unsupported `sort` → **`400`** `invalid_sort`. Bad `order` → **`400`** `invalid_order`. Bad or mismatched `cursor` → **`400`** `invalid_cursor`.

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

**Limitations:** There is no total-count field; clients page with `has_more` / `next_cursor` only. Very large imports still require multiple requests to walk the full inventory.

### GET /v1/scans/{scanID}/endpoints/{endpointID}

Returns **`200`** with one **endpoint detail** object for an imported `scan_endpoints` row belonging to the scan. **`404`** when the scan or endpoint id is missing or the endpoint does not belong to the scan.

**Shape:** All **endpoint read** fields (same as **`items[]`** in the list) with **`summary` always present** (grounded counts: baseline executions, mutation executions, findings for this `scan_endpoint_id`; same SQL semantics as list `include_summary=true`). Plus:

**Implementation note (performance, not wire):** Inventory **list** pages with `include_summary=true` use scan-scoped SQL CTEs that pre-aggregate execution and finding counts per `scan_endpoint_id`, then join to the page of endpoints. **Endpoint detail** (`GET .../endpoints/{endpointID}`) uses **correlated subqueries for the same count fields** scoped to that single row so the database does not build the full per-endpoint aggregate map for the whole scan. **`include_summary=false`** on the list skips both CTEs and per-row summary columns (wire shape unchanged).

- **`investigation`** (persisted facts only; never percentages or synthetic rollups): optional nested blocks are omitted when there is nothing to say.
  - **`baseline`**, **`mutation`**: each appears only when the corresponding **`summary`** count is greater than zero and a latest stored row exists for that phase; **`latest_response_status`** is the HTTP status on the **newest** `execution_record` for this endpoint and phase (`created_at` desc, `id` desc tie-break in PostgreSQL).
  - **`findings`**: present when **`summary.findings_recorded` > 0**; **`by_assessment_tier`** maps **non-zero** counts for linked rows whose **`assessment_tier`** is exactly `confirmed`, `tentative`, or `incomplete` (after trim). Findings linked to the endpoint but with another tier contribute to **`summary.findings_recorded`** only—they do not appear in **`by_assessment_tier`** until they match one of those three stored values.
- **`drilldown`**: Path-only prefixes for this scan and endpoint (leading `/v1/...`, no host) plus **query fragments** for filtered lists:
  - `scan_id` (same as **`scan_id`** on the parent object; repeated for a self-contained drilldown block).
  - `scan_endpoint_id` (same UUID as **`id`**).
  - `endpoints_inventory_path`, `endpoint_detail_path` (this resource), `executions_list_path`, `findings_list_path`, **`run_status_path`** (same scan’s orchestration read model as **`GET .../run/status`**).
  - `executions_list_query` / `findings_list_query`: literal substring `scan_endpoint_id=<uuid>` (no leading `?`). **Filtered scan-scoped list:** `{executions_list_path}?{executions_list_query}` (same pattern for findings). **Limitation:** paths omit the API base URL; callers prepend their configured origin.

**List vs detail:** **`GET .../endpoints`** does **not** include **`investigation`** or **`drilldown`** on each item; only this detail route does.

The response does **not** embed execution or finding rows; use list routes with that filter (and per-row GETs for full HTTP or `evidence_summary`) to inspect related data.

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

Lists stored HTTP exchanges for the scan. **Response shape:** JSON object with **`items`** (array of **execution list** rows) and **`meta`** (pagination). **`GET .../executions/{executionID}`** returns the full **execution read** (includes redacted `request` / `response` bodies and header maps); list rows intentionally omit those objects so operators can page large runs without shipping duplicate body payload.

**Execution list row** fields:

| Field | Meaning |
| --- | --- |
| `id`, `scan_id`, `scan_endpoint_id`, `created_at`, `duration_ms` | Identity and timing. |
| `phase` | `baseline` or `mutated` (persisted execution phase). |
| `execution_kind` | Same value as `phase`; use either for filtering mentally; both are always set together. |
| `mutation_rule_id` | Rule id for mutated rows (empty for baseline). |
| `candidate_key` | Mutation work-item key for **mutated** rows only (resume/dedup); empty for baseline. |
| `request_summary` | Concise view: `method`, `url_short` (length-capped from stored URL), `header_count`, `body_byte_length` (derived from the **same** redacted persisted fields as detail `request`). |
| `response_summary` | Concise view: **`status_code`** (same integer as persisted HTTP status; use list filters `response_status` against this value), `content_type`, `header_count`, `body_byte_length` (aligned with detail `response`). |
| **`execution_detail_path`** | Path-only **`GET /v1/scans/{scan_id}/executions/{id}`** for this row (same string as on **`ExecutionRead.execution_detail_path`**). |

**List vs detail:** Shared keys follow the same order as **`ExecutionRead`** except list rows omit **`request`** / **`response`** body objects. **`request_summary`** / **`response_summary`** on a list item must match the corresponding fields on **`GET .../executions/{executionID}`** for the same row (redaction rules identical). List rows include **`execution_detail_path`** so operators can open the detail GET without synthesizing URLs from **`id`** and **`scan_id`**.

**Pagination (keyset cursor):** `meta.limit` echoes the applied page size (default **50**, maximum **200**). `meta.has_more` is true when more rows exist. `meta.next_cursor` is an opaque string: pass it as **`cursor`** on the next request (with the **same** `sort`, `order`, and narrow filters) to continue. Ordering is deterministic: primary sort key, then `created_at`, then row `id`. Cursors are validated against `sort` and `order`; a mismatched cursor returns `400` `invalid_cursor`.

**Supported `sort` (executions):** `created_at` (default), `phase` (baseline before mutated for `asc`, reversed for `desc`). Other values return `400` `invalid_sort`.

**Supported `order`:** `asc` (default), `desc`. Invalid values return `400` `invalid_order`.

**Not supported:** `offset` (returns `400` `unsupported_query_parameter`); use `cursor` only.

**Filters** (combined with AND): `phase`, `execution_kind` (alias; must match `phase` if both set, else `400` `invalid_filter`), `scan_endpoint_id` (**must be a UUID** when set), `rule_id` or **`mutation_rule_id`** (same filter against persisted `rule_id` on mutated rows; if both are set they must agree, else `400` `invalid_filter`), `response_status` (**integer 100–599**; if the query key is present, the value must be valid, else `400` `invalid_filter`). `phase` / `execution_kind`, when set, must be exactly `baseline` or `mutated` (`400` `invalid_filter` otherwise).

### GET /v1/scans/{scanID}/executions/{executionID}

Returns one **execution read** object (full redacted `request` / `response` plus summaries) when it belongs to the scan.

**Detail semantics:** `execution_kind` always equals `phase` (`baseline` or `mutated`). `request` / `response` are the persisted redacted snapshots. `request_summary` / `response_summary` repeat method, shortened URL, header/body **counts**, and status/content-type derived from those same persisted fields—they do not add new HTTP material (use for quick parity with list rows). For mutated rows, `mutation_rule_id` and `candidate_key` identify the rule work item; baseline rows omit them. **`executions_list_path`** is path-only **`GET /v1/scans/{scan_id}/executions`** (same prefix as run-status **`drilldown.executions_list_path`**). **`execution_detail_path`** repeats this row’s detail path for list/detail parity.

**Baseline vs mutated comparison:** use **`operator_guide.cross_phase_filter_hint`** (and optionally **`scan_endpoint_id`** list filters) to load the sibling phase for the same imported operation; **`evidence_comparison_guide`** on a finding detail names the two execution GETs when both ids exist.

**`operator_guide` (always present on detail):** read-model hints only. `phase_role` is `baseline_pre_mutation` or `mutated_post_mutation` (scanner vocabulary for how this row relates to the mutation pipeline). `linkage_narration` is a short English line on how to pair baseline vs mutated executions for diff-backed findings. `summaries_mirror_redacted_snapshots` states that the summary objects repeat snapshot fields (counts, lengths, shortened URL, status)—not an alternate HTTP capture. `phase_execution_kind_alignment` states that **`phase`** and **`execution_kind`** are identical on this API. `summaries_list_detail_parity` states that the summary objects match the **GET .../executions** list row for the same execution id (for diffing list vs detail responses). **`cross_phase_filter_hint`** states how to **`GET .../executions?scan_endpoint_id=...`** to list the other phase for the same imported operation when you do not already know the sibling execution id. Local Docker **`make benchmark-findings-local`** / **`make e2e-local`** assert all six keys are present and non-empty on sampled execution GETs (shared **`scripts/read_trust_assert.sh`**).

**Errors:** `400` `invalid_scan_id` or `invalid_execution_id` when path segments are not UUIDs; `404` `not_found` when the scan does not exist, or the execution is missing or not scoped to that scan.

### GET /v1/scans/{scanID}/findings

Lists findings for the scan. **Response shape:** object with **`items`** (**finding list** rows) and **`meta`** (same pagination fields as executions).

Rows are produced only after a mutation pass when matchers pass with complete diff evaluation. Each **finding list** row mirrors **`FindingRead` field order** for shared keys (without **`evidence_summary`**): **`id`**, **`scan_id`**, **`rule_id`**, **`category`**, **`severity`**, **`rule_declared_confidence`**, **`assessment_tier`**, **`summary`**, **`evidence_uri`**, optional **`scan_endpoint_id`**, optional merged **`baseline_execution_id` / `mutated_execution_id`**, **`created_at`**, **`finding_detail_path`** (path-only **`GET /v1/findings/{id}`** — finding detail is not nested under **`/scans/{scan_id}`** on the wire), and optional compact **`evidence_inspection`** (`diff_point_count`, **`matcher_passed`**, **`matcher_failed`**, **`matcher_total`** = passed+failed when matchers exist—no **`matcher_outcomes`** array). Execution linkage is **only** on the list row; the list inspection object does not repeat those IDs. The list does **not** include raw **`evidence_summary`** (use **`GET /v1/findings/{findingID}`** or **`finding_detail_path`** for the full read model and per-matcher rows).

**Pagination:** Same cursor model as executions (`limit` default 50, max 200; `cursor` + `meta.next_cursor`). Deterministic tie-break: after primary sort, `created_at`, then `id`.

**Supported `sort` (findings):** `created_at` (default), `severity` (order: info, low, medium, high, critical for `asc`).

**Supported `order`:** `asc` (default), `desc`.

**Not supported:** `offset` (`400` `unsupported_query_parameter`). Unsupported `sort` for this resource (e.g. `phase`) returns `400` `invalid_sort`.

**Non-overlapping semantics:** `severity` is impact; `assessment_tier` is post-run evidence assessment (`confirmed` / `tentative` / `incomplete`); `rule_declared_confidence` is rule-pack signal quality from YAML (not a substitute for `assessment_tier`). **`summary`** is human-oriented text; **`evidence_inspection`** is derived from **`evidence_summary`** only (matcher rows and diff point count). **`baseline_execution_id` / `mutated_execution_id`** on the row are merged from `evidence_summary` when the finding columns are empty so linkage is visible without parsing JSON.

Optional **filter** query parameters (all exact match, ANDed with pagination): `assessment_tier` (**`confirmed`**, **`tentative`**, or **`incomplete`**), **`severity`** (**`info`**, **`low`**, **`medium`**, **`high`**, **`critical`**), **`rule_declared_confidence`** (**`high`**, **`medium`**, **`low`**), **`rule_id`**, **`scan_endpoint_id`** (UUID of an imported endpoint row; limits findings to that operation). Invalid enum-like values or a bad UUID for **`scan_endpoint_id`** return `400` `invalid_filter`.

**List vs detail:** **`GET /v1/findings/{findingID}`** returns **`FindingRead`**: all persisted columns including optional **`evidence_summary`** plus full **`evidence_inspection`** (sorted **`matcher_outcomes`** and execution linkage inside the block when present), always-on **`read_trust_legend`**, optional **`evidence_comparison_guide`** (scan-scoped execution GET paths when both **`baseline_execution_id`** and **`mutated_execution_id`** resolve), and optional **`operator_assessment`**. **`findings_list_path`** is path-only **`GET /v1/scans/{scan_id}/findings`** (same as run-status **`drilldown.findings_list_path`**). **`finding_detail_path`** matches the list row’s **`finding_detail_path`**. List rows use the compact inspection counts only; per-matcher lines, **`read_trust_legend`**, **`evidence_comparison_guide`**, **`operator_assessment`**, and the raw JSON blob are **detail-only**.

**Limitation:** Clients that relied on **`matcher_outcomes`** inside list **`evidence_inspection`** must call **`GET /v1/findings/{id}`** for those rows.

## Findings

### GET /v1/findings/{findingID}

Returns one **finding read** object (full columns including **`evidence_summary`** when stored), with **`evidence_inspection`** when applicable. This shape is **richer** than **`items[]`** from **`GET .../scans/{id}/findings`**. **`findings_list_path`** and **`finding_detail_path`** are path-only navigation (back to the scan’s findings list and this resource, respectively).

**Field roles:** `severity` (impact bucket), `rule_declared_confidence` (YAML `confidence` only—signal quality), `assessment_tier` (post-run evidence sufficiency: **`confirmed`** / **`tentative`** / **`incomplete`**), and `summary` (one-line operator text) are **orthogonal**—do not treat `rule_declared_confidence` as the same signal as `assessment_tier` or as `severity`. **`evidence_summary`** is the raw persisted JSON (`schema_version`, matcher/diff payload, **`assessment_tier`**, **`rule_declared_confidence`**, **`rule_severity`** and **`impact_severity`** as the same impact snapshot, optional **`assessment_notes`**, optional **`interpretation_hints`**); **`assessment_notes`** record weak-signal causes; **`interpretation_hints`** record tier policy codes (e.g. **`interpretation_body_similarity_min_below_0_9_keeps_tentative_tier`**, **`outcome_insufficient_evidence_for_confirmed_tier`** for **`incomplete`**). **`rule_severity` / `impact_severity`** align with top-level **`severity`**, not with **`assessment_tier`** or **`confidence`**. The finding row plus API normalization (trimmed strings, merged execution IDs) remains the primary operator surface. **`evidence_inspection.matcher_outcomes`** is a stable, sorted-by-`index` subset for quick review; it does not replace reading **`evidence_summary`** when debugging evaluator-specific fields.

**`read_trust_legend` (always present on detail):** a fixed glossary object whose **property names match the payload keys** they describe (`severity`, `rule_declared_confidence`, `assessment_tier`, `evidence_summary`, `evidence_inspection`, `operator_assessment`). Values are **stable strings** explaining how each axis or derived block relates to the others—**not** row-specific values and **not** a repeat of **`operator_assessment.evidence_sufficiency_guide`**. Use it to compare severity (impact), declared confidence (authoring), tier (post-run sufficiency), raw **`evidence_summary`**, derived **`evidence_inspection`**, and optional **`operator_assessment`** without inferring from field names alone. **`make benchmark-findings-local`** and **`make e2e-local`** assert non-empty strings for every legend key on real GETs (via **`scripts/read_trust_assert.sh`**).

**`evidence_comparison_guide` (optional):** when both **`baseline_execution_id`** and **`mutated_execution_id`** are non-empty (after merge from **`evidence_summary`**) on **`GET /v1/findings/{id}`**, detail includes a single string that names those two ids, states that matchers used their diff, and gives the two **`GET /v1/scans/{scan_id}/executions/{id}`** URLs for full redacted HTTP. It does **not** replace **`evidence_inspection.matcher_outcomes`** (what matched); it only makes the baseline/mutated comparison leg easier when opening executions.

**`operator_assessment` (optional):** when at least one of tier gloss or mirrored codes is non-empty, detail includes this object. It does **not** duplicate top-level **`severity`**, **`rule_declared_confidence`**, or **`assessment_tier`**. Fields: **`evidence_sufficiency_guide`** — stable one-line scanner-policy gloss for **`assessment_tier`** (why the row is read as confirmed vs tentative vs incomplete at a high level); **`assessment_note_codes`** — same strings as **`evidence_summary.assessment_notes`** (trimmed), for triage without parsing JSON; **`scanner_policy_hints`** — same strings as **`evidence_summary.interpretation_hints`**. **Interpretation:** **`confirmed`** means matchers passed with evidence the scanner treats as complete for this row and no tier cap applies; **`tentative`** means matchers passed but declared confidence, impact, or weak matcher signals cap the tier; **`incomplete`** means baseline/mutated linkage, HTTP bar, or diff evaluation did not meet the confirmed tier. When **`operator_assessment`** is absent, there was no tier-specific gloss and no notes/hints to mirror (operators still have top-level **`assessment_tier`** and raw **`evidence_summary`** if stored). The legend entry **`read_trust_legend.operator_assessment`** still explains what that **block** means when present; the top-level **`operator_assessment`** key is omitted when empty.

**Errors:** `400` `invalid_finding_id` when `{findingID}` is not a UUID; `404` when absent.

Rule load failures (`GET /v1/rules`) return `rule_load_failed` with a **numbered, multi-line** validation message when YAML fails validation.

### GET /v1/findings/{findingID}/evidence

Returns finding-bound evidence from the persisted **`evidence_artifacts`** row (baseline/mutated request/response bodies and **`diff_summary`** as stored). **Not** the same resource as `execution_records`; use scan-scoped execution GETs for full exchange snapshots linked by `baseline_execution_id` / `mutated_execution_id`.

**Errors:** `400` `invalid_finding_id` when `{findingID}` is not a UUID; `404` when no artifact exists for that finding.

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
