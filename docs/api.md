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
| `progress` | Counters from the scan row plus `endpoints_discovered` from imported endpoint count (no percentages or estimates). |
| `coverage` | Auth/security hints (no secrets). |
| `diagnostics` | Grounded `blocked_detail` / `skipped_detail` entries (`code` + optional `detail`) derived only from persisted scan columns and endpoint inventory; `phase_failed_next_step` and `resume_recommended` when `phase` is `failed`. |

**Compatibility (non-canonical):** the `compatibility` object duplicates `scan.id` -> `scan_id`, `run.phase` -> `phase`, `scan.status` -> `scan_status`, and `run.orchestrator_error` -> `last_error` for older clients. **`compatibility.last_error` is only the orchestrator failure** (same as `run.orchestrator_error`), not baseline/mutation sub-messages, so it does not overlap those fields.

**Failure semantics:** When `phase` is `failed`, read `run.orchestrator_error` first. If baseline or mutation sub-status is `failed`, the corresponding `*_run_error` holds that runner’s message. When baseline status is **not** `failed`, `baseline_run_error` is omitted/empty in the response even if a stale string remains in storage (same for mutation). This keeps “current sub-run failure” unambiguous.

**Diagnostics codes (may appear; all factual):** `no_imported_endpoints`, `declared_security_without_auth`, `baseline_not_recorded`, `zero_mutation_candidates` — see unit tests for exact trigger conditions. No speculative reasons are invented.

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

Returns persisted `ScanEndpoint` rows (JSON array), ordered by `path_template` then `method`.

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

Lists stored HTTP exchanges for the scan, oldest first. Response body is a JSON array of **execution read** objects (stable envelope: `request` and `response` snapshots, `mutation_rule_id` for mutated rows, `phase`, `duration_ms`, `created_at`). Optional query parameters:

- `phase`: `baseline` or `mutated`
- `scan_endpoint_id`: UUID of an imported endpoint
- `rule_id`: exact `mutation_rule_id` filter (mutated rows only store this when tied to a rule candidate)
- `response_status`: exact HTTP status code integer (e.g. `200`)

### GET /v1/scans/{scanID}/executions/{executionID}

Returns one execution read object when it belongs to the scan. `404` when missing or mismatched.

### GET /v1/scans/{scanID}/findings

Lists findings for the scan. Rows are produced only after a mutation pass when matchers pass with complete diff evaluation. Each row uses **non-overlapping** fields:

- `severity`: impact bucket from the rule (not the same as assessment tier).
- `rule_declared_confidence`: author-declared signal from rule YAML (`high`, `medium`, `low`).
- `assessment_tier`: post-run tier (`confirmed`, `tentative`, `incomplete`) from evidence and matcher strength rules.
- `evidence_summary`: structured JSON (schema version 1) with matcher outcomes, diff points, and both `assessment_tier` and `rule_declared_confidence` duplicated for bundle consumers.

Optional query parameters (all exact match, ANDed):

- `assessment_tier`
- `severity`
- `rule_declared_confidence`

## Findings

### GET /v1/findings/{findingID}

Returns one finding row with the same fields as the list endpoint (`severity`, `rule_declared_confidence`, `assessment_tier`, `summary`, `evidence_summary`, execution linkage ids).

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
