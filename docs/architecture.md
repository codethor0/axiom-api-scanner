# Architecture

This document describes the intended shape of Axiom at V1. The repository includes PostgreSQL-backed scans, imported OpenAPI endpoints per scan, baseline HTTP execution, sequential mutation execution for supported V1 rule families, a narrow baseline-vs-mutated diff engine, and finding creation when matchers pass with complete evidence. Threat-class language in rules and categories aligns with the [OWASP API Security Top 10](https://owasp.org/API-Security/) (for example API1 BOLA/IDOR and mass assignment) as a roadmap baseline, without claiming full coverage.

## Components

### Control plane (`cmd/api`, `internal/api`)

The HTTP API creates and updates scans, imports OpenAPI specs per scan, lists imported endpoints, triggers baseline and mutation execution, lists execution records, transitions scan state, lists findings, serves finding-tied evidence rows, and exposes rules. Baseline and mutation runs execute in-process today; the worker binary remains a stub for future asynchronous work.

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

Finding model includes linkage fields (`scan_endpoint_id`, `baseline_execution_id`, `mutated_execution_id`), `confidence` and `status` tiers (`confirmed` / `tentative` / `incomplete`), human `summary`, and `evidence_summary` JSON. Tiers are derived from rule severity, declared rule confidence, weak matcher signals (substring or similarity below 0.9), and HTTP evidence completeness (execution ids and successful status codes). Findings are inserted only from the mutation path when diff evaluation passes and is not incomplete; `evidence_artifacts` still hold raw request/body snapshots and a short diff line.

### Shared HTTP helpers (`internal/executil`)

URL join and scope checks, response body normalization consistent with baseline evidence, header capture, and redaction of credential-like headers before persistence.

### Storage (`internal/storage`, `internal/storage/postgres`, `migrations/`)

Repositories cover scans (target, auth, baseline and mutation progress, `findings_count`), endpoint replace or list, execution insert, list, and get-by-scan, findings list, get, and create (with evidence artifact and `findings_count` bump). SQL migrations via **golang-migrate** (see [development.md](development.md)).

## Current execution flow (implemented)

1. Create scan; optionally set `base_url` and `auth_headers` at creation or via `PATCH`.
2. `POST /v1/scans/{id}/specs/openapi` persists `scan_endpoints` for that scan (full replace; stale rows removed).
3. `POST /v1/scans/{id}/executions/baseline` runs the baseline runner, writes baseline `execution_records`, updates baseline progress fields, returns runner output plus planner decisions and a capped mutation preview from `AXIOM_RULES_DIR`.
4. `POST /v1/scans/{id}/executions/mutations` runs mutations sequentially from the same rule set (no broad concurrency). Writes mutated `execution_records`, runs diff vs the latest baseline per endpoint, and persists findings plus evidence when all matchers pass.
5. `GET /v1/scans/{id}/executions` and `GET .../executions/{executionID}` return stored exchanges (optional `phase` and `scan_endpoint_id` query filters on the list).

## Limitations (honest)

- No worker offload, no parallel mutation flood, no arbitrary fuzzing.
- Diff matchers are intentionally narrow; weak matcher configurations yield `tentative` findings rather than `confirmed` when evidence is otherwise complete.
- No automated mutated-vs-mutated comparisons; only baseline vs one mutated execution per candidate step.

## Observability

Use structured logs with stable field names. Never log secrets, tokens, or raw credentials. Treat logs as event streams suitable for aggregation (Twelve-Factor). Persisted request or response headers use the same redaction rules as baseline for known sensitive names.
