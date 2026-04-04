# Testing

## Evaluator quick path (first 10 minutes)

1. **Skim positioning:** [comparison.md](comparison.md) — what Axiom is, the four V1 families, and what it does **not** claim.
2. **Pick a proof path:**
   - **No Docker:** `make ci-unit` from repo root (same spirit as CI’s compile/test gate; Postgres integration tests **skip** unless `AXIOM_TEST_DATABASE_URL` is set).
   - **Docker fixtures:** `make e2e-local` then, when that finishes, `make benchmark-findings-local` — or run **`make release-candidate-proof`** once to run both **in order** (avoids port **8080** fights).
3. **Interpret green:** use the **Proof matrix** below — **GitHub Actions does not substitute** for local Docker; it complements it.
4. **Optional read:** [benchmark-results.md](benchmark-results.md) for expected `bench_summary` rows; [faq.md](faq.md) for CI vs local and common pitfalls.
5. **API container only (no httpbin e2e):** build with **`make docker-build-api`**, run with **`DATABASE_URL`** set (`make docker-run-api`), or one-shot **`make docker-api-smoke`** to assert **`GET /v1/rules`** against an ephemeral Postgres. This is **packaging smoke**, not the **e2e-local** / **benchmark** proof matrix.

## Docker API image (packaging)

The repo [`Dockerfile`](../Dockerfile) builds **`cmd/api`** only. The image includes **`/app/migrations`** and **`/app/rules`**; it does **not** contain Postgres or fixture targets. Typical use:

| Step | Command / note |
| --- | --- |
| Build | `make docker-build-api` (override tag: `AXIOM_IMAGE=ghcr.io/org/axiom:v0.1.0-rc.1 docker build ...` or set **`AXIOM_IMAGE`**) |
| Run | `export DATABASE_URL=postgres://...` then `make docker-run-api`, or use `docker run` as in [README.md](../README.md#quickstart-docker) |
| Smoke test | `make docker-api-smoke` — builds, starts **postgres:16-alpine** on a throwaway network, curls **`/v1/rules`**, removes containers |

**CI:** workflow runs **`bash -n`** on [`scripts/docker_api_smoke.sh`](../scripts/docker_api_smoke.sh) only; it does **not** build or push the image. **Publishing to GHCR/Docker Hub** is an org-specific step (credentials, tag policy).

## Release candidate proof

For a **single local recipe** that mirrors a maintainer sign-off (`check-migrations`, `go vet`, `golangci-lint`, full `go test`, then Docker **`e2e-local`** **then** **`benchmark-findings-local`** in sequence):

```text
make release-candidate-proof
```

**What it is not:** a replacement for GitHub Actions (runs on your machine); **is:** the full **local** proof stack in one command. **Requirements:** Docker, `curl`, `jq`, Go; run from repository root. Default compose ports are **54334**, **18080**, **18081**, **8080** (see **Local Docker prerequisite summary** below). To exercise **PostgreSQL integration tests** inside `go test`, export **`AXIOM_TEST_DATABASE_URL`** to a dedicated database before running the Makefile target (otherwise those tests are skipped when the variable is unset).

Release notes template: [CHANGELOG.md](../CHANGELOG.md). Positioning: [comparison.md](comparison.md). Expected benchmark outcomes (Axiom-only): [benchmark-results.md](benchmark-results.md).

## CI vs local

**GitHub Actions** (`.github/workflows/ci.yml`), on `push` and `pull_request` to `main`:

| Step | Purpose |
| --- | --- |
| `./scripts/check_migrations.sh` | Every `migrations/*.up.sql` has a matching `.down.sql`, expected `NNNNNN_name.up.sql` / `.down.sql` naming |
| `bash -n` on `scripts/read_trust_assert.sh`, `scripts/e2e_local.sh`, `scripts/benchmark_findings_local.sh` | Shell syntax check so shared jq assertion helpers and local proof entrypoints stay parseable (does **not** execute Docker stacks or curl the API) |
| `go vet ./...` | Standard vet checks |
| `golangci-lint run` | Linters from [.golangci.yml](../.golangci.yml) (includes `govet` with shadow detection) |
| `go test ./... -count=1` | Full module tests with `AXIOM_TEST_DATABASE_URL` pointing at a job service container (`postgres:16-alpine`) |

**Not in CI** (heavy, flaky, or third-party stack): `make e2e-local`, `make benchmark-findings-local`, `make e2e-crapi`, `make e2e-crapi-auth`, manual targets, or anything requiring cloned OWASP crAPI images beyond this workflow. There is **no** workflow job that runs the Docker benchmark or e2e compose stack today; reproducibility depends on contributors using the Makefile targets locally. **Contract parity:** `internal/api/read_contract_test.go` asserts list envelopes include **`items`**, **`meta`**, and **`scan_navigation`** (and matches `NewScanListNavigation`) for both executions and findings lists; **`TestContract_scanRunStatus_wireKeys_withCoverageAndDiagnostics`** also requires **`drilldown`** list paths (**`findings_list_path`**, **`executions_list_path`**, **`run_status_path`**) to match **`NewScanListNavigation`**. **`navigation_drilldown_contract_test.go`** asserts endpoint **`drilldown`** filtered lists still carry that same **`scan_navigation`**, that **`TestContract_findingsList_itemIdOpensFindingDetail`** / **`TestContract_executionList_itemIdOpensExecutionDetail`** **`GET`** list rows resolve to **`200`** detail, and (elsewhere in that file) full run-status **`drilldown`** shape vs **`scanRunDrilldownHints`**. Local scripts additionally assert live HTTP: list **`scan_navigation`** equals **`GET .../run/status`** **`drilldown`** for those three paths (see **`scripts/read_trust_assert.sh`**).

### Proof matrix (CI vs local vs environment)

Use this table before release to see what is actually exercised; it does not replace reading the workflow file.

| What | GitHub Actions | Local `make e2e-local` | Local `make benchmark-findings-local` |
| --- | --- | --- | --- |
| Migration SQL layout (`check_migrations.sh`) | yes | no (compose + app apply migrations separately) | no |
| **`bash -n`** on proof scripts (`read_trust_assert.sh`, `e2e_local.sh`, `benchmark_findings_local.sh`) | yes | scripts run for real (**syntax-only step does not prove jq logic**) | scripts run for real |
| **`go vet`**, **golangci-lint**, **`go test ./...`** | yes (postgres service sets **`AXIOM_TEST_DATABASE_URL`**) | optional | optional |
| In-memory HTTP contracts (`httptest`): list envelopes, **run-status `drilldown`** vs **`NewScanListNavigation`**, **filtered** executions/findings lists **`scan_navigation`**, list **`finding_detail_path`** / **`execution_detail_path`** open **`200`** detail | yes | no | no |
| Docker Compose (Postgres, httpbin, optional rate stub) | no | yes | yes |
| Live **`curl`** + **`jq`** read paths, legend/guide shapes, **`scan_navigation`** === **`drilldown`** on real API | no | yes | yes |
| Builtin rule tier / **`bench_*`** / **`bench_summary_matrix`** | no | no | yes |

**Environment-dependent:** CI needs the workflow Postgres service. Local flows need Docker (or equivalent), free default ports, **`curl`**, **`jq`**, and matching **`go`**. **`go test`** without **`AXIOM_TEST_DATABASE_URL`** skips postgres integration packages (see **Without Postgres** below). If **`AXIOM_TEST_DATABASE_URL`** is set to a **down** database, postgres integration tests **fail**; unset the variable or point it at a live Postgres instance. **`bash -n`** does not execute scripts; a broken **`jq`** filter could still pass CI until local Docker runs or someone executes the script by hand.

**Port contention:** **`make e2e-local`** and **`make benchmark-findings-local`** both bind **`AXIOM_HTTP_ADDR`** (default **`127.0.0.1:8080`**). Run them **sequentially**, or use **`make release-candidate-proof`**, or set non-conflicting **`AXIOM_HTTP_ADDR`** / **`AXIOM_URL`** per script docs.

### Local Docker prerequisite summary (e2e + benchmark)

Run **`make e2e-local`** or **`make benchmark-findings-local`** from the **repository root** after a normal clone (scripts assert **`deploy/e2e/docker-compose.yml`**, **`rules/`**, **`migrations/`**, and **`testdata/e2e/httpbin-openapi.yaml`** exist; the benchmark also needs **`testdata/e2e/bench-rate-limit-stub.yaml`**).

| Need | Notes |
| --- | --- |
| **Docker daemon** | Scripts print a clear error if `docker info` fails (daemon stopped or permission denied). |
| **Commands** | **`docker`**, **`curl`**, **`jq`**, **`go`** (same **`go` version family** as **`go.mod`**). |
| **Default localhost ports** | Postgres **54334**, httpbin **18080**, rate stub **18081**, API **8080**. If a port is busy, override **`DATABASE_URL`**, **`HTTPBIN_URL`**, **`RATE_STUB_URL`**, and matching **`AXIOM_HTTP_ADDR`** + **`AXIOM_URL`** (benchmark and e2e use **`127.0.0.1:8080`** by default). |
| **Failure hints** | Scripts tail **`docker compose logs`** for Postgres or the rate stub when health checks time out; API wait failures mention **`AXIOM_HTTP_ADDR`** / **`AXIOM_URL`** mismatch. Shared checks live in **`scripts/local_stack_preflight.sh`**. |

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
| Handler | Scan create, control, OpenAPI, PATCH scan, **endpoint list** (`items`/`meta`, keyset `cursor`, optional `summary` persisted-row counts, `include_summary=false` contract, `handlers_scan_contract_test` + `endpoints_contract_test`), **endpoint detail** (`GET .../endpoints/{endpointID}`: always-on summary + `investigation` + `drilldown` path/query hints; list items exclude `investigation`/`drilldown`; `endpoints_detail_contract_test`), **executions list** (`request_summary` / `response_summary` shape incl. `status_code`; **`execution_detail_path`**; validated filters; no `request`/`response` keys on items) vs **execution detail** (full redacted snapshots; **`executions_list_path`** + **`execution_detail_path`**; mandatory **`operator_guide`** keys in `read_contract_test`; list/detail summary parity in `handlers_list_contract_test` + `read_contract_test`), **findings list** (`FindingListItem` matches detail core fields; **`finding_detail_path`**; compact list `evidence_inspection` without `matcher_outcomes`; no `evidence_summary`; optional **`scan_endpoint_id`** filter) vs **finding detail** (`FindingRead`; **`findings_list_path`**; merged linkage + sorted `matcher_outcomes`; always-on **`read_trust_legend`**; optional **`operator_assessment`** when tier gloss or mirrored notes/hints exist—`finding_read_test` + `read_contract_test`), baseline/mutations contract cases, read contract tests for evidence artifacts + invalid UUID `400`s (`read_contract_test`, `handlers_contract_test`), **scan run status** (`drilldown` path hints; `summary` vs `progress` consistency, `findings_summary.total` presence, canonical groups, drift/coverage/diagnostics; successful path calls `assertScanRunStatusSummaryProgressFindings`; **`run.progression_source`** / **`run.findings_recording_status`** wire keys in `handlers_scan_contract_test` + `scanrun_semantics_test`). **`navigation_drilldown_contract_test`:** run-status **`drilldown`** matches `scanRunDrilldownHints`, **`scan_detail_path`** resolves to **`200`** scan GET, endpoint drilldown resolves filtered execution/finding lists and **`run_status_path`** to **`200`** run status, execution list exposes **`mutation_rule_id` / `candidate_key`** on mutated rows when present. **`scanrun_summary_contract_test`:** run status **`summary`** and **`findings_summary`** nested keys; endpoint inventory list vs detail **`summary`** parity; **`include_summary=false`** omits **`summary`** on list items. **`handlers_list_contract_test`:** findings/executions canonical wire keys, list **`scan_navigation`** matches **`NewScanListNavigation`** (aligned with run-status drilldown list paths), list `evidence_inspection` must not embed `matcher_outcomes`, `response_summary` key contract, filtered list `400`/`200`, list/detail core field parity tests. **`scanrun_consistency_test`:** pure `scanRunConsistencyLines` cases (findings drift, progress counters, family tallies, protected-route bucket mismatches, read-model context, unclassified mutated executions). **`handlers_scan_contract_test`:** wire shape and **diagnostic `category`** on representative blocked, auth-limited, and inconsistent scenarios. **Read-model projections:** `ListScanEndpointsForRunStatus` planner parity vs full list (`scanrun_readmodel_test`); `SummarizeFindingsForScan` list parity in mem. Integration (`AXIOM_TEST_DATABASE_URL`): `TestEndpointReplace_integration` asserts **`ListScanEndpointsForRunStatus`** matches full list ids and omits content-type columns; `TestFindingWrite_integration` asserts aggregates, **`ListEndpointInventoryPage`** summaries, **`GetEndpointInventory`** matches list row counts, and detail-only investigation facts (latest phase status + tier buckets) when the DB path is exercised. Skipped when env unset. |
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
3. Exercises, via `curl` + `jq`, the **first scan** (ad-hoc runners): create scan, import `testdata/e2e/httpbin-openapi.yaml`, list endpoints, `POST .../executions/baseline`, `POST .../executions/mutations`, **`GET .../executions/{id}`** (detail: `phase`/`execution_kind` alignment, request vs `request_summary` parity), **`GET .../run/status`** (drilldown paths, diagnostics arrays), **`GET .../endpoints/{endpointID}`** (investigation + drilldown query fragment contains `scan_endpoint_id=`), executions list and findings list envelopes (**`scan_navigation`** paths for the scan + parity with **`run/status`** **`drilldown`** via **`read_trust_assert.sh`**), **finding detail** (`severity`, `assessment_tier`, `rule_declared_confidence`, `evidence_inspection` present), evidence GET, optional **filtered findings** `?scan_endpoint_id=...` when rows exist.
4. **Second scan** (orchestrator): import same fixture, `POST .../run` with `action: start` (expects terminal `run.phase == findings_complete` on the response), `POST .../run` with `action: resume` (phase unchanged), **`GET .../run/status`**, then **`GET`** the URL from `drilldown.scan_detail_path` and assert the scan id.

**Fixed target assumptions:** spec `servers` and scan `base_url` point at **`127.0.0.1:18080`** (httpbin from compose). Rules load from repo **`rules/`** via `AXIOM_RULES_DIR`. No outbound traffic leaves localhost except to that httpbin port.

**Fixture (`testdata/e2e/httpbin-openapi.yaml`):** **`GET /anything/{id}`** declares **`ApiKeyAuth`** so **`security_scheme_hints`** are non-empty on that row. The builtin IDOR example rule lists **`authenticated_session`** among prerequisites; the planner requires declared security on the import for that prerequisite. Benchmark and e2e scans typically do **not** send **`auth_headers`** unless you add them; httpbin still serves **200** for these probes.

**Proven when green:** safe V1 import, inventory, baseline + mutation persistence, execution and finding read models, run-status envelope shape, endpoint drilldown fragments, orchestrated run through `findings_complete`, and idempotent `resume` on an already-complete run.

**What the harness does not prove:** crAPI/Juice Shop behavior, token validation for declared-secure operations, every rule family on every endpoint shape, or CI reproducibility (this flow is **local Docker only**).

**Ad-hoc vs orchestration (`run.phase`):** After **`POST .../executions/baseline`** and **`POST .../executions/mutations`**, persisted **`run_phase`** remains the default **`planned`**; **`summary` / `progress`** counters and execution/finding rows still reflect completed work. **`GET .../run/status`** shows **`run.progression_source == "adhoc"`**, **`run.findings_recording_status == "complete"`** when the mutation pass succeeded, and **`run.phase == "planned"`** for that first scan. The orchestrated second scan shows **`run.progression_source == "orchestrator"`** and **`run.phase == "findings_complete"`**. Only **`POST .../run`** advances **`run_phase`** through the orchestration graph; **`progression_source`** distinguishes ad-hoc driver usage without new storage.

### Finding-quality benchmark (local, httpbin and nginx rate stub)

**Entrypoint:** `make benchmark-findings-local` (runs `scripts/benchmark_findings_local.sh`).

**Stack:** `deploy/e2e/docker-compose.yml` starts **`axiom-pg`**, **`httpbin`** (`127.0.0.1:18080`), and **`rate-limit-bench`** (`nginx:alpine` on **`127.0.0.1:18081`**, config in **`deploy/e2e/rate-limit-bench/nginx.conf`**). **`scripts/e2e_local.sh`** still starts only Postgres + httpbin; the benchmark additionally needs the stub for scan B. Target rules: **`rules/builtin/*.example.yaml`**.

**Scan A (httpbin, `testdata/e2e/httpbin-openapi.yaml`):** **`GET /anything/{id}`**, **`GET /status/200`**, **`POST /post`**. Imports declare **`ApiKeyAuth`** on **`/anything/{id}`** for IDOR planner eligibility.

| Family | Builtin rule id | Proven outcome (scan A) |
| --- | --- | --- |
| IDOR path swap | **`axiom.idor.path_swap.v1`** | **One** finding, **`tentative`**, weak-similarity assessment note pair on **`summary`** / **`evidence_summary`**. |
| Mass assignment | **`axiom.mass.privilege_merge.v1`** | **One** **`confirmed`**; **`assessment_notes`** empty/absent. |
| Path normalization | **`axiom.pathnorm.variant.v1`** | **Two** findings (**`/anything/{id}`** and **`/status/200`**), both **`tentative`** (builtin uses **`response_body_similarity`** @ **0.85**). |
| Rate-limit headers | **`axiom.ratelimit.header_rotate.v1`** | **No** persisted finding row: httpbin responses do not satisfy **`response_header_differs_from_baseline`** for **`X-RateLimit-Remaining`** (**fixture-limited** target behavior: matchers never pass, so this is an honest **no-finding**, not a tentative row). |

**Scan B (stub, `testdata/e2e/bench-rate-limit-stub.yaml`):** single **`GET /rate-probe`** with **`base_url` `http://127.0.0.1:18081`**. Nginx maps **`X-Forwarded-For: 127.0.0.2`** (the builtin rotation value) to **`X-RateLimit-Remaining: 7`**, default clients to **`10`**, so the rate-limit rule can produce a **`confirmed`** finding (**confirmed useful signal** on this fixture: header differential after rotation). The same endpoint remains eligible for path normalization; the double-slash variant still matches **`location /rate-probe`** in nginx, so scan B also yields **one** **`tentative`** path-normalization row (same weak-signal class as httpbin pathnorm; **fixture coupling**: stub layout makes pathnorm fire here too, without changing scanner tier rules). **Total: two** findings on scan B (pathnorm + rate limit).

**Interpreting benchmark outcomes (operator trust):**

| Outcome | Meaning on these fixtures |
| --- | --- |
| **Confirmed finding** | Matchers passed; tier **`confirmed`**; **`assessment_notes`** and **`interpretation_hints`** empty/absent. Example: mass assignment on scan A; rate-limit header rotation on scan B. |
| **Tentative weak-signal finding** | Matchers passed; tier **`tentative`** with weak-signal **`assessment_notes`** (e.g. similarity **min_score** < 0.9); **`interpretation_hints`** includes tier-policy codes such as **`interpretation_body_similarity_min_below_0_9_keeps_tentative_tier`**; **`summary`** includes **`; assessment:`** and **`; interpretation:`** segments. Example: IDOR and path normalization rows on scan A; pathnorm on scan B. |
| **No-finding (no row)** | Mutation pass completed; rule produced **zero** finding rows because matchers did not pass or evaluation was incomplete (not stored). Example: **`axiom.ratelimit.header_rotate.v1`** on scan A only. |
| **Fixture-limited vs fixture-coupled** | **Fixture-limited** describes the **target** (httpbin cannot satisfy rate-limit header diff), not scanner output. **Fixture-coupled** describes **which rows appear** on a given stub (scan B adds pathnorm + rate on one URL); **`interpretation_hints`** stay scanner-policy codes only. |
| **Fixture-artifact (benchmark pathnorm on stub)** | Scan B’s **`tentative`** **`axiom.pathnorm.variant.v1`** row uses the **same** scanner policy as httpbin tentatives (`interpretation_body_similarity_min_below_0_9_keeps_tentative_tier` in **`interpretation_hints`**). The extra code **`bench_fixture_artifact_pathnorm_on_single_stub_route`** (below) marks that this row exists because the **stub OpenAPI** exposes a single GET where path normalization still matches—**not** because the scanner invented a new weak-signal class. |

**Harness-only `bench_*` codes** (comma-separated in script output; **not** written to **`evidence_summary`**): implemented in **`internal/findings`** as **`BenchmarkHarnessRowNotes`** / **`BenchmarkHarnessNoFindingNotes`**, printed via **`go run ./scripts/benchharness`**, and asserted in **`scripts/benchmark_findings_local.sh`** (expectations mirror **`benchmark_harness_test.go`**).

| Code prefix / example | Role |
| --- | --- |
| **`bench_target_httpbin_v1`**, **`bench_target_rate_stub`** | Which benchmark scan (`target_label`) produced the outcome. |
| **`bench_scanner_tentative_weak_similarity_policy`** | Tentative tier is driven by scanner policy (weak body similarity path), same on every target. |
| **`bench_scanner_confirmed_useful_signal`** | Confirmed tier after matchers passed with no weak-signal capping on that row. |
| **`bench_fixture_layout_httpbin_openapi_operations`** | Tentative rows from the **httpbin** import (multi-operation layout); **genuine** weak-signal in the sense of “import + rules,” not stub-only. |
| **`bench_fixture_artifact_pathnorm_on_single_stub_route`** | **Fixture-artifact** nuance: pathnorm **`tentative`** on scan B only—single stub route still satisfies the same rule mechanics as httpbin. |
| **`bench_fixture_context_*`** | Confirmed rows tied to **mass on httpbin** or **rate header differential on nginx stub** (what the fixture enables, without changing tier logic). |
| **`bench_no_finding_absent_row`**, **`bench_fixture_limit_httpbin_rate_header_matcher_unsatisfied`** | Expected **no row** for rate-limit rule on httpbin after mutations (matchers never satisfied). |

**`bench_summary_matrix` (end of successful run):** eight **`bench_summary v=1`** lines (four builtin rules **`×`** scan A + scan B) with stable **`key=value`** fields: **`phase`** (`scan_A` \| `scan_B`), **`target_label`**, **`rule_id`**, **`family`** (same tokens as **`rule_family_coverage`** in [docs/api.md](api.md): `idor_path_or_query_swap`, `mass_assignment_privilege_injection`, `path_normalization_bypass`, `rate_limit_header_rotation`), **`finding_rows`**, **`outcome`**. Outcome strings come from **`findings.BenchmarkOutcomeClass`** (see **`internal/findings/benchmark_outcome.go`** and **`benchmark_outcome_test.go`**):

| **`outcome=`** | Meaning |
| --- | --- |
| **`outcome_confirmed_useful`** | At least one row; **`confirmed`** tier (matchers passed, no weak-signal cap on that row). |
| **`outcome_tentative_weak_signal`** | At least one row; **`tentative`** (or **`incomplete`**) tier. |
| **`outcome_fixture_limited_no_row`** | **Zero** rows **and** this rule is the httpbin rate-limit case (target cannot produce header differential). |
| **`outcome_not_exercised_on_target`** | **Zero** rows because this scan produced no finding for that rule (e.g. idor/mass on stub-only import). |

A ninth line documents **CI**: **`phase=ci_github_actions`**, **`outcome=outcome_not_in_matrix`**, meaning the matrix is **not** produced in GitHub Actions (Docker benchmark only). A short **`bench_outcome_legend`** block repeats the four outcomes in prose. **`go run ./scripts/benchharness -outcome-class`** and **`-rule-family`** emit single values for scripts.

**Read-path checks:** **`GET .../run/status`** (**`adhoc`**, **`findings_recording_status` `complete`**; scan B asserts **`rule_family_coverage.rate_limit_header_rotation.exercised`**), endpoint detail, finding detail (**`evidence_summary.assessment_notes`** and **`interpretation_hints`** parity with **`summary`** for tentatives; both empty for confirmed mass/rate rows), execution detail, list envelopes (**`scan_navigation`** on **`GET .../findings`** and **`GET .../executions`** vs run-status **`drilldown`**, once findings exist), plus harness **`bench_*`** lines and **`go run ./scripts/benchharness`** parity for each expected row. **`read_trust_legend`** on finding detail (including **`finding_list_row`**) and **`operator_guide`** (seven keys, including **`cross_phase_filter_hint`** and **`phase_summary_compare_hint`**) on execution detail are asserted via **`scripts/read_trust_assert.sh`**. **`assert_finding_evidence_comparison_when_paired`** requires non-empty **`evidence_comparison_guide`** whenever both execution ids are present on a finding GET (benchmark + e2e when findings exist).

**What local flows do not prove:** that the *wording* inside legend/guide strings matches a golden file—only that the JSON shape and non-empty gloss fields are present end-to-end.

**What it does not prove:** Production CDN rate-limit behavior, multi-operation OpenAPI `servers` mixing, or coverage beyond these two local targets. The nginx map is **test-only**; it is not a general rate-limit emulator.

**Limitations:** **`make e2e-local`** does not require the stub; only **`make benchmark-findings-local`** pulls **`nginx:alpine`** if missing. CI does **not** run this Docker flow.

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
