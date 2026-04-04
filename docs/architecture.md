# Architecture

This document describes the intended shape of Axiom at V1. The repository includes PostgreSQL-backed scans, imported OpenAPI endpoints per scan, baseline HTTP execution, sequential mutation execution for supported V1 rule families, a narrow baseline-vs-mutated diff engine, and finding creation when matchers pass with complete evidence. Threat-class language in rules and categories aligns with the [OWASP API Security Top 10](https://owasp.org/API-Security/) (for example API1 BOLA/IDOR and mass assignment) as a roadmap baseline, without claiming full coverage.

## Components

### Control plane (`cmd/api`, `internal/api`)

The HTTP API creates and updates scans, imports OpenAPI specs per scan, lists imported endpoints, triggers baseline and mutation execution (ad hoc or via **scan run** orchestration), lists execution records, transitions scan state, lists findings, serves finding-tied evidence rows, and exposes rules. Baseline and mutation runs execute in-process today; the worker binary remains a stub for future asynchronous work.

### Scan run orchestrator (`internal/orchestrator`)

A narrow `Service` sequences the safe V1 path: ensure scan is addressable, advance persisted `run_phase`, run baseline (skipping HTTP when the scan row already records a successful completed baseline unless `force_rerun_baseline`), load rules, build mutation work, run mutations, then advance phases to `findings_complete` and mark the scan completed. On **`resume`** after `failed`, if baseline already succeeded, it reconciles `run_phase` to `baseline_complete` first so the operator read model does not imply baseline work is pending when persisted counters say it finished. It is **synchronous** and single-goroutine from the caller (HTTP handler); cancellation is honored via request context and scan cancel flag between phase steps. Phase transitions are validated in `internal/engine` (`ValidateScanRunTransition`, including optional `baseline_complete` -> `baseline_running` only when forcing baseline rerun); the database stores `scans.run_phase` and `scans.run_error`.

### Worker (`cmd/worker`)

Placeholder process for future background execution. Baseline runs use `POST .../executions/baseline`; mutation passes use `POST .../executions/mutations`. Do not assume the worker performs them yet.

### Engine (`internal/engine`)

Domain types: `Scan` (including baseline and mutation progress plus `findings_count`), legacy `Endpoint` DTO, `ScanEndpoint` (persisted import row), `ExecutionRecord` (baseline or mutated traffic).

### OpenAPI (`internal/spec/openapi`)

`ExtractEndpointSpecs` validates OpenAPI 3.x and returns a deterministic ordered list including method, path, security scheme names, request or response content types, and whether `application/json` is declared for the request body.

### Planning (`internal/plan/v1`)

Pure planner: given a `ScanEndpoint` and loaded `rules.Rule` set, emits deterministic eligibility decisions for V1 families (IDOR path or query swap, mass assignment, path normalization, rate-limit header rotation) with string reasons.

### Mutation candidates (`internal/mutate`)

Generates ordered, human-readable mutation candidates from a rule plus endpoint context. Does not perform HTTP.

### Baseline executor (`internal/executor/baseline`)

Sequential client for GET and JSON POST operations only. Joins `scan.base_url` with path templates using deterministic placeholder substitution (`pathutil`). Injects scan `auth_headers`, enforces URL prefix scope, redacts sensitive headers in persisted metadata, records `execution_records` rows (phase `baseline`). Rejects cross-origin redirects.

### Mutation executor (`internal/executor/mutation`)

Sequential HTTP for the same supported methods as baseline. Reuses `BuildRequest` for V1 mutations only (`BuildWorkList` ties planner output to candidates). Requires `baseline_run_status == succeeded` on the scan before running. Persists `execution_records` with phase `mutated` and optional `rule_id`, updates mutation counters on `scans`, and calls the diff engine after each exchange.

### Diff (`internal/diff/v1`)

Evaluates typed rule `matchers` for a baseline vs mutated `ExecutionRecord` pair with AND semantics. Unsupported matcher kinds yield an incomplete result (no finding). Prefers no finding when evaluation cannot be completed or matchers fail. Successful evaluation emits per-matcher summaries used in finding evidence payloads.

### Rules (`internal/rules`, `rules/`)

Typed YAML rules: mutations, matchers (including `status_differs_from_baseline`, `response_body_substring`, `json_path_equals`, `response_header_differs_from_baseline`, plus existing V1 kinds), loaded for planning, preview, mutation execution, and diffing. For `safety.mode` `safe` and `passive`, validation enforces a single mutation per rule, non-contradictory matchers, family-appropriate matcher allowlists (for example IDOR rules cannot use header-only matchers; rate-limit header rules must include a header-related matcher), and `response_body_similarity.min_score >= 0.75`. `confidence` in YAML must be one of `high`, `medium`, `low`. `full` mode may still declare multiple mutations for advanced packs.

### Findings (`internal/findings`)

Finding rows store **severity** (impact), **rule_declared_confidence** (YAML `high`/`medium`/`low`), and **assessment_tier** (`confirmed`/`tentative`/`incomplete`) as separate columns—no field overloads. Assessment uses rule severity, declared confidence, weak matcher signals, and HTTP evidence completeness. `evidence_summary` JSON duplicates tier and declared confidence for artifact bundles. Findings are inserted only from the mutation path when diff evaluation passes and is not incomplete; `evidence_artifacts` still hold raw request/body snapshots and a short diff line.

HTTP API lists executions as **execution read** projections: nested `request` / `response` objects, `mutation_rule_id` instead of a generic `rule_id` at the top level, and `response.status_code` naming for clarity.

### Shared HTTP helpers (`internal/executil`)

URL join and scope checks, response body normalization consistent with baseline evidence, header capture, and redaction of credential-like headers before persistence.

### Storage (`internal/storage`, `internal/storage/postgres`, `migrations/`)

Repositories cover scans (target, auth, `run_phase`, `run_error`, baseline and mutation progress, `findings_count`), endpoint replace or list, execution insert, list, get-by-scan, mutation lookup by `(scan, endpoint, rule, candidate_key)`, findings list, get, get-by-evidence-tuple, and create (with evidence artifact and `findings_count` bump). Unique constraints prevent duplicate findings for the same evidence tuple. SQL migrations via **golang-migrate** (see [development.md](development.md)).

## Current execution flow (implemented)

1. Create scan; optionally set `base_url` and `auth_headers` at creation or via `PATCH`.
2. `POST /v1/scans/{id}/specs/openapi` persists `scan_endpoints` for that scan (full replace; stale rows removed).
3. Either run steps manually or use **`POST /v1/scans/{id}/run`** with `action: start` (or `resume` after failure) to run baseline then mutations in one synchronous orchestration with explicit `run_phase` updates.
4. `POST /v1/scans/{id}/executions/baseline` runs the baseline runner alone, writes baseline `execution_records`, updates baseline progress fields, returns runner output plus planner decisions and a capped mutation preview from `AXIOM_RULES_DIR`.
5. `POST /v1/scans/{id}/executions/mutations` runs mutations sequentially from the same rule set (no broad concurrency). Writes mutated `execution_records` (with stable `candidate_key` for resume), runs diff vs the latest baseline per endpoint, and persists findings plus evidence when all matchers pass. Re-running with the same candidate reuses the stored mutated execution and does not insert a second finding for the same evidence tuple.
6. `GET /v1/scans/{id}/executions` and `GET .../executions/{executionID}` return stored exchanges (optional `phase` and `scan_endpoint_id` query filters on the list).
7. `GET /v1/scans/{id}/run/status` returns canonical `scan`, `run`, `progress`, `summary` (derived scan-row counters plus imported endpoint count), `findings_summary` (aggregates from stored findings), `rule_family_coverage` (mutated `execution_records` joined to rules from `AXIOM_RULES_DIR`, four V1 families; optional `not_exercised_contributors` for planner and declared-secure/auth facts), `guidance` (action `next_steps`; always an array), `coverage` (auth hints), **`protected_route_coverage`** (import and execution tallies by OpenAPI-declared security on each `scan_endpoints` row; baseline 401/403/2xx counts for declared-secure operations only), and `diagnostics` (always includes `blocked_detail`, `skipped_detail`, `consistency_detail`; `skipped_detail` may add route/auth visibility from stored executions only). `compatibility` holds legacy mirrors (`scan_id`, `phase`, `scan_status`, `last_error` = orchestrator error only). Operator errors are split: `run.orchestrator_error` vs sub-runner fields only when those sub-statuses are `failed`. **`diagnostics.consistency_detail`** compares persisted scan columns and list outputs; inconsistencies are reported only as diagnostics—no automatic repair.

## Limitations (honest)

- Orchestration is in-process and blocking for the HTTP request that calls `start`/`resume`; there is no job queue or worker handoff yet. `GET .../run/status` is read-only but may list findings and executions to build summaries and consistency checks; it does not broaden write surface or start work.
- **Read-model consistency** is observability-only: for example `findings_count` on `scans` vs `len(findings)` for the scan, baseline/mutation done-vs-total on the scan row, and rule-family mutated counts vs mutated execution row counts. Drift indicates a bug or partial write; operators see stable codes under `diagnostics.consistency_detail`.
- **Declared-secure / protected-route visibility** uses only `security_scheme_hints` on imported rows plus `execution_records` joined by `scan_endpoint_id`. It does not prove OAuth flows, token lifetimes, or correct authorization decisions—only stored traffic and status codes against operations the spec marked as secured.
- No worker offload, no parallel mutation flood, no arbitrary fuzzing.
- Diff matchers are intentionally narrow; weak matcher configurations yield `tentative` findings rather than `confirmed` when evidence is otherwise complete.
- No automated mutated-vs-mutated comparisons; only baseline vs one mutated execution per candidate step.

## Observability

Use structured logs with stable field names. Never log secrets, tokens, or raw credentials. Treat logs as event streams suitable for aggregation (Twelve-Factor). Persisted request or response headers use the same redaction rules as baseline for known sensitive names.
