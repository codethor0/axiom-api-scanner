# Testing

## CI vs local

**GitHub Actions** (`.github/workflows/ci.yml`), on `push` and `pull_request` to `main`:

| Step | Purpose |
| --- | --- |
| `./scripts/check_migrations.sh` | Every `migrations/*.up.sql` has a matching `.down.sql`, expected `NNNNNN_name.up.sql` / `.down.sql` naming |
| `go vet ./...` | Standard vet checks |
| `golangci-lint run` | Linters from [.golangci.yml](../.golangci.yml) (includes `govet` with shadow detection) |
| `go test ./... -count=1` | Full module tests with `AXIOM_TEST_DATABASE_URL` pointing at a job service container (`postgres:16-alpine`) |

**Not in CI** (heavy, flaky, or third-party stack): `make e2e-local`, `make benchmark-findings-local`, `make e2e-crapi`, `make e2e-crapi-auth`, manual targets, or anything requiring cloned OWASP crAPI images beyond this workflow.

**Mirror CI locally:** with Postgres listening and a dedicated database:

```text
export AXIOM_TEST_DATABASE_URL='postgres://USER:PASS@HOST:PORT/DBNAME?sslmode=disable'
make ci
```

**Without Postgres** (integration tests skip inside `go test`):

```text
make ci-unit
```

**Workflow YAML (optional):** `make workflow-lint` runs [actionlint](https://github.com/rhysd/actionlint) on `.github/workflows/*.yml` via `go run` (network on first run). This is not part of `make ci` / `make ci-unit`.

## Goals

- Prove correctness of parsers, validation, and planning logic.
- Keep tests deterministic: normalize timestamps, random identifiers, and unstable ordering before golden comparisons.
- Fail CI on regressions in rule loading, OpenAPI extraction, and public HTTP contracts.

## Layers

| Layer | Scope |
| --- | --- |
| Unit | Rule validation, OpenAPI `ExtractEndpointSpecs`, path template helper, V1 planner, mutation generator, `internal/diff/v1` matchers, `internal/executil` redaction, mutation `BuildRequest` scope checks, scan run phase graph and forced baseline transition (`internal/engine`), orchestrator dependency guards, resume without baseline HTTP when baseline already succeeded (`internal/orchestrator`), mutation resume/dedupe (`runner_verify_test`). |
| Handler | Scan create, control, OpenAPI, PATCH scan, **endpoint list** (`items`/`meta`, keyset `cursor`, optional `summary` persisted-row counts, `include_summary=false` contract, `handlers_scan_contract_test` + `endpoints_contract_test`), **endpoint detail** (`GET .../endpoints/{endpointID}`: always-on summary + `investigation` + `drilldown` path/query hints; list items exclude `investigation`/`drilldown`; `endpoints_detail_contract_test`), **executions list** (`request_summary` / `response_summary` shape incl. `status_code`; validated filters; no `request`/`response` keys on items) vs **execution detail** (full redacted snapshots; list/detail summary parity in `handlers_list_contract_test` + `read_contract_test`), **findings list** (`FindingListItem` matches detail core fields; compact list `evidence_inspection` without `matcher_outcomes`; no `evidence_summary`; optional **`scan_endpoint_id`** filter) vs **finding detail** (`FindingRead`; merged linkage + sorted `matcher_outcomes` in `finding_read_test`), baseline/mutations contract cases, read contract tests for evidence artifacts + invalid UUID `400`s (`read_contract_test`, `handlers_contract_test`), **scan run status** (`drilldown` path hints; `summary` vs `progress` consistency, `findings_summary.total` presence, canonical groups, drift/coverage/diagnostics; successful path calls `assertScanRunStatusSummaryProgressFindings`; **`run.progression_source`** / **`run.findings_recording_status`** wire keys in `handlers_scan_contract_test` + `scanrun_semantics_test`). **`navigation_drilldown_contract_test`:** run-status **`drilldown`** matches `scanRunDrilldownHints`, **`scan_detail_path`** resolves to **`200`** scan GET, endpoint drilldown resolves filtered execution/finding lists and **`run_status_path`** to **`200`** run status, execution list exposes **`mutation_rule_id` / `candidate_key`** on mutated rows when present. **`scanrun_summary_contract_test`:** run status **`summary`** and **`findings_summary`** nested keys; endpoint inventory list vs detail **`summary`** parity; **`include_summary=false`** omits **`summary`** on list items. **`handlers_list_contract_test`:** findings/executions canonical wire keys, list `evidence_inspection` must not embed `matcher_outcomes`, `response_summary` key contract, filtered list `400`/`200`, list/detail core field parity tests. **`scanrun_consistency_test`:** pure `scanRunConsistencyLines` cases (findings drift, progress counters, family tallies, protected-route bucket mismatches, read-model context, unclassified mutated executions). **`handlers_scan_contract_test`:** wire shape and **diagnostic `category`** on representative blocked, auth-limited, and inconsistent scenarios. **Read-model projections:** `ListScanEndpointsForRunStatus` planner parity vs full list (`scanrun_readmodel_test`); `SummarizeFindingsForScan` list parity in mem. Integration (`AXIOM_TEST_DATABASE_URL`): `TestEndpointReplace_integration` asserts **`ListScanEndpointsForRunStatus`** matches full list ids and omits content-type columns; `TestFindingWrite_integration` asserts aggregates, **`ListEndpointInventoryPage`** summaries, **`GetEndpointInventory`** matches list row counts, and detail-only investigation facts (latest phase status + tier buckets) when the DB path is exercised. Skipped when env unset. |
| Baseline | `internal/executor/baseline/runner_test` uses `httptest` plus in-memory store; performs one GET baseline. |
| Integration | `internal/storage/postgres` when `AXIOM_TEST_DATABASE_URL` is set (runs `dbmigrate.Up` from `AXIOM_TEST_MIGRATIONS_DIR` or repo-root `migrations/`, through `000007_scan_run_orchestration` and earlier). Includes **run-status endpoint projection** checks in `TestEndpointReplace_integration`, **`SummarizeFindingsForScan`** vs list in `TestFindingWrite_integration`, and **endpoint inventory** per-endpoint counts. |
| End-to-end | `make e2e-local` (httpbin plumbing) and `make e2e-crapi` (OWASP crAPI + same V1 checks); see **Local Docker end-to-end** below. Finding-quality tier checks on the same httpbin fixture: **`make benchmark-findings-local`** (see below). |

## Scan run status: consistency vs diagnostics

**Consistency (`diagnostics.consistency_detail`, `category: inconsistent`):** unit tests in `internal/api/scanrun_consistency_test.go` assert specific `code` values when persisted counters, aggregates, tallies, or coverage buckets disagree. The handler must not silently reconcile these fields.

**Operational state (`blocked_detail`, `skipped_detail`, optional `auth_limit`):** contract tests in `internal/api/handlers_scan_contract_test.go` assert that representative preconditions (no endpoints, missing auth headers on secured operations) emit the expected `code` and `category`, without treating them as storage corruption.

**Parity:** in-memory stores exercise the same consistency logic as production callers; PostgreSQL-specific **finding summarize** and **run-status endpoint projection** integration tests still require `AXIOM_TEST_DATABASE_URL` (see postgres package).

## Fixtures

Store OpenAPI snippets and HTTP transcripts under a dedicated `testdata` tree (to be expanded). Remove volatile headers and dates when diffing responses.

## Running tests

```text
go test ./...
go vet ./...
```

The module `go` directive may require a newer toolchain than 1.22; use the version named in `go.mod`.

PostgreSQL-backed tests live in `internal/storage/postgres`. They apply **all** migrations from `migrations/` (including finding `evidence_summary`) via `internal/dbmigrate` on each run. Required environment variable:

| Variable | Purpose |
| --- | --- |
| `AXIOM_TEST_DATABASE_URL` | PostgreSQL URL for a database the tests may migrate (use a dedicated test database, not production). |

Optional:

| Variable | Purpose |
| --- | --- |
| `AXIOM_TEST_MIGRATIONS_DIR` | Absolute or relative path to SQL migrations. When unset, postgres integration tests resolve the repository `migrations/` directory from the `internal/storage/postgres` package path (normal clone layout), not from the shell `cwd`. |

Run only the postgres package (recommended after schema changes):

```text
export AXIOM_TEST_DATABASE_URL='postgres://USER:PASS@HOST:PORT/DBNAME?sslmode=disable'
cd /path/to/axiom-api-scanner
go test ./internal/storage/postgres/... -count=1 -v
```

Example with Docker (ephemeral server, empty database `axiom_verify`):

**Prerequisites:** the Docker daemon must be running (`docker info` shows a healthy Server section, not `Cannot connect to the Docker daemon`). On macOS, start Docker Desktop first. If you already have PostgreSQL listening elsewhere, skip Docker and set `AXIOM_TEST_DATABASE_URL` to that DSN instead.

```text
docker rm -f axiom-pg-test 2>/dev/null || true
docker run -d --name axiom-pg-test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=axiom_verify -p 54333:5432 postgres:16-alpine
# wait until the server accepts connections (e.g. a few seconds), then:
export AXIOM_TEST_DATABASE_URL='postgres://postgres:test@127.0.0.1:54333/axiom_verify?sslmode=disable'
go test ./internal/storage/postgres/... -count=1 -v
```

Migrations run in order through the latest file (currently `000007_scan_run_orchestration`); `dbmigrate.Up` stops on the first apply error.

Integration tests: `TestScanLifecycle_integration`, `TestEndpointReplace_integration`, `TestFindingWrite_integration`. They are skipped when `AXIOM_TEST_DATABASE_URL` is unset.

Makefile helper if defined (see [development.md](development.md)):

```text
make test-integration
```

Linting:

```text
make lint
```

## Local Docker end-to-end (V1)

E2E scripts use **canonical** run payloads in `jq` checks (for example `.run.phase == "findings_complete"` on `POST .../run` responses). Legacy mirrors live under `.compatibility` if needed.

**Goal:** Prove the supported safe V1 path against **local** targets only (no unsolicited scans of third-party APIs).

**Axiom-managed stack** (repository root):

```text
docker info   # must show a healthy server
make e2e-local
```

This runs `scripts/e2e_local.sh`, which:

1. Starts `deploy/e2e/docker-compose.yml` services **`axiom-pg`** (Postgres on `127.0.0.1:54334`, DB `axiom_e2e`, user/password `axiom`) and **`httpbin`** (`mccutchen/go-httpbin` on `127.0.0.1:18080`).
2. Builds `bin/axiom-api-e2e` and listens on `127.0.0.1:8080` with `DATABASE_URL=postgres://axiom:axiom@127.0.0.1:54334/axiom_e2e?sslmode=disable`.
3. Exercises, via `curl` + `jq`, the **first scan** (ad-hoc runners): create scan, import `testdata/e2e/httpbin-openapi.yaml`, list endpoints, `POST .../executions/baseline`, `POST .../executions/mutations`, **`GET .../executions/{id}`** (detail: `phase`/`execution_kind` alignment, request vs `request_summary` parity), **`GET .../run/status`** (drilldown paths, diagnostics arrays), **`GET .../endpoints/{endpointID}`** (investigation + drilldown query fragment contains `scan_endpoint_id=`), findings list, **finding detail** (`severity`, `assessment_tier`, `rule_declared_confidence`, `evidence_inspection` present), evidence GET, optional **filtered findings** `?scan_endpoint_id=...` when rows exist.
4. **Second scan** (orchestrator): import same fixture, `POST .../run` with `action: start` (expects terminal `run.phase == findings_complete` on the response), `POST .../run` with `action: resume` (phase unchanged), **`GET .../run/status`**, then **`GET`** the URL from `drilldown.scan_detail_path` and assert the scan id.

**Fixed target assumptions:** spec `servers` and scan `base_url` point at **`127.0.0.1:18080`** (httpbin from compose). Rules load from repo **`rules/`** via `AXIOM_RULES_DIR`. No outbound traffic leaves localhost except to that httpbin port.

**Fixture (`testdata/e2e/httpbin-openapi.yaml`):** **`GET /anything/{id}`** declares **`ApiKeyAuth`** so **`security_scheme_hints`** are non-empty on that row. The builtin IDOR example rule lists **`authenticated_session`** among prerequisites; the planner requires declared security on the import for that prerequisite. Benchmark and e2e scans typically do **not** send **`auth_headers`** unless you add them; httpbin still serves **200** for these probes.

**Proven when green:** safe V1 import, inventory, baseline + mutation persistence, execution and finding read models, run-status envelope shape, endpoint drilldown fragments, orchestrated run through `findings_complete`, and idempotent `resume` on an already-complete run.

**What the harness does not prove:** crAPI/Juice Shop behavior, token validation for declared-secure operations, every rule family on every endpoint shape, or CI reproducibility (this flow is **local Docker only**).

**Ad-hoc vs orchestration (`run.phase`):** After **`POST .../executions/baseline`** and **`POST .../executions/mutations`**, persisted **`run_phase`** remains the default **`planned`**; **`summary` / `progress`** counters and execution/finding rows still reflect completed work. **`GET .../run/status`** shows **`run.progression_source == "adhoc"`**, **`run.findings_recording_status == "complete"`** when the mutation pass succeeded, and **`run.phase == "planned"`** for that first scan. The orchestrated second scan shows **`run.progression_source == "orchestrator"`** and **`run.phase == "findings_complete"`**. Only **`POST .../run`** advances **`run_phase`** through the orchestration graph; **`progression_source`** distinguishes ad-hoc driver usage without new storage.

### Finding-quality benchmark (local, httpbin)

**Entrypoint:** `make benchmark-findings-local` (runs `scripts/benchmark_findings_local.sh`).

**Stack:** Same as `e2e-local`: `deploy/e2e/docker-compose.yml` (`axiom-pg` + httpbin), `bin/axiom-api-bench`, `DATABASE_URL` / `AXIOM_RULES_DIR` / migrations as in the e2e script. Target: **`testdata/e2e/httpbin-openapi.yaml`** and **`rules/`** ( **`rules/builtin/*.example.yaml`** ).

**V1 families exercised (same single scan):**

| Family | Builtin rule id | Proven outcome on this fixture |
| --- | --- | --- |
| IDOR path swap | **`axiom.idor.path_swap.v1`** | Exactly **one** finding, **`assessment_tier`** **`tentative`**; **`response_body_similarity`** @ **0.85** yields assessment notes **`weak_body_similarity_matcher`** and **`similarity_min_score_0.85`** (mirrored in **`summary`** and **`evidence_summary.assessment_notes`**). **`confirmed`** requires no weak-signal matchers (e.g. **`similarity.min_score` >= 0.9** and no body-substring matcher). |
| Mass assignment | **`axiom.mass.privilege_merge.v1`** | Exactly **one** finding, **`confirmed`**; **`evidence_summary.assessment_notes`** empty/absent. |
| Path normalization | **`axiom.pathnorm.variant.v1`** | Exactly **one** finding, **`tentative`**; same weak-similarity note pair as IDOR on this fixture. |
| Rate-limit headers | **`axiom.ratelimit.header_rotate.v1`** | **No** finding row: mutation may run, but **`response_header_differs_from_baseline`** on **`X-RateLimit-Remaining`** does not succeed against httpbin’s responses (header absent or unchanged). This is an intentional **no-finding** path, not a skipped family. |

**Read-path checks:** asserts **`GET .../run/status`** (**`progression_source`** **`adhoc`**, **`findings_recording_status`** **`complete`**), **`GET .../endpoints/{id}`** ( **`investigation`** + **`drilldown`** ), **`GET .../findings/{id}`** (tentative rows include the weak-similarity **`assessment_notes`**; confirmed mass assignment omits them), and **`GET .../executions/{id}`** for a linked mutated execution.

**What it does not prove:** Query-swap IDOR variants (not in this spec), real rate-limit appliances, **`X-RateLimit-Remaining`** semantics on production targets, or coverage beyond the four builtin examples. Single-endpoint concurrency and large imports are out of scope.

**Prerequisites:** `docker`, `curl`, `jq`, `go`.

**Teardown:**

```text
docker compose -f deploy/e2e/docker-compose.yml down
```

### OWASP crAPI (intentionally vulnerable API)

**Entrypoint:**

```text
docker info
make e2e-crapi
# optional: JWT via identity API + authenticated scan
make e2e-crapi-auth
```

This runs `scripts/e2e_crapi.sh`, which:

1. **Clones** (first run only) `develop` [OWASP/crAPI](https://github.com/OWASP/crAPI) into `.cache/crapi` (gitignored).
2. Runs **`docker compose -f docker-compose.yml --compatibility up -d`** from `.cache/crapi/deploy/docker` (upstream stack; multiple images).
3. Waits for **`http://127.0.0.1:8888/health`** (`crapi-web`).
4. Starts **Axiom Postgres** from `deploy/e2e/docker-compose.yml` (`axiom-pg` on `54334`) if not already up.
5. Builds **`bin/axiom-api-e2e`**, listens on **`127.0.0.1:8080`**.
6. Creates a scan with **`base_url` = `http://127.0.0.1:8888`** (matches the official spec `servers` in `openapi-spec/crapi-openapi-spec.json`).
7. **`POST /v1/scans/{id}/specs/openapi`** with the **clone-local** `crapi-openapi-spec.json` (JSON), then **baseline**, **mutations**, **findings** list, **finding + evidence** GETs, and a second scan with orchestrated **`run`** `start` + `resume`.

**OpenAPI source:** The spec is read from the **same commit as the cloned repo**, not from a live HTTP URL on crAPI (the gateway does not need to expose Swagger for import). Raw upstream URL for reference only: `https://raw.githubusercontent.com/OWASP/crAPI/develop/openapi-spec/crapi-openapi-spec.json`.

**What is actually exercised (unauthenticated scan in `make e2e-crapi`):** V1 **GET** and **JSON POST** baseline/mutation paths against crAPI’s reachable operations without `auth_headers`; **safe** rules under `rules/`; **diff/matchers** and **finding + evidence_summary**; **read APIs**; **orchestrator** idempotent `resume`.

**Authenticated leg (`make e2e-crapi-auth`):** Same as `e2e-crapi`, then **API-only** `POST /identity/api/auth/signup` and `POST /identity/api/auth/login` against **local crAPI** to obtain a JWT (`token` in JSON). A second Axiom scan is created with **`auth_headers`** `Authorization: Bearer <jwt>`, then import, baseline, mutations, and findings run again. The script asserts at least one **baseline** `POST` to **`/community/api/v2/community/posts`** did **not** return **401** (token accepted). It does **not** prove every bearer-protected challenge in crAPI, full role separation, or browser OTP flows.

**Not exercised:** Juice Shop, broad rule packs beyond repo `rules/`, non-safe modes, or guaranteed coverage of every path in the spec. Multi-step flows (refresh tokens, email OTP) are out of scope for this harness.

**Teardown crAPI:** from `.cache/crapi/deploy/docker`: `docker compose -f docker-compose.yml down` (destroys crAPI volumes if you add `-v`; only do that when you intend to reset lab data).

**Ports:** crAPI uses **8888** (and upstream services use other host ports such as **8025** for Mailhog). Axiom e2e uses **8080** and **54334**. If **8080** is already taken by another process, set **`AXIOM_HTTP_ADDR`** (and matching **`AXIOM_URL`**) before running the script, or stop the conflicting listener; the script does not auto-pick a free port.

**Juice Shop (secondary):** `docker compose -f deploy/e2e/docker-compose.yml --profile juice up -d` exposes `127.0.0.1:13000`. Prefer browser/app flows upstream; API OpenAPI varies by version—validate imports manually.

**Swagger Petstore:** use only for harmless spec experiments if needed; prefer local httpbin for automation.

**Known limitations:** `e2e-local` does not start crAPI; `e2e-crapi` does not start httpbin. Fixed ports are intentional for reproducibility; resolve conflicts by stopping other listeners or overriding env vars documented above. Orchestration is synchronous and holds the HTTP connection for `start`/`resume`.

## Evidence normalization

When comparing responses, strip or replace fields such as `Date`, `X-Request-Id`, and server-specific tokens. Document normalization rules next to golden files when they are introduced.
