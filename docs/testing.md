# Testing

## Goals

- Prove correctness of parsers, validation, and planning logic.
- Keep tests deterministic: normalize timestamps, random identifiers, and unstable ordering before golden comparisons.
- Fail CI on regressions in rule loading, OpenAPI extraction, and public HTTP contracts.

## Layers

| Layer | Scope |
| --- | --- |
| Unit | Rule validation, OpenAPI `ExtractEndpointSpecs`, path template helper, V1 planner, mutation generator, `internal/diff/v1` matchers, `internal/executil` redaction, mutation `BuildRequest` scope checks, scan run phase graph (`internal/engine`), orchestrator dependency guards, mutation resume/dedupe (`runner_verify_test`). |
| Handler | Scan create, control, OpenAPI, PATCH scan, executions list/detail, baseline/mutations contract cases, scan run status/cancel and mem dedupe assertions using `httptest` and in-memory repository fakes (no database). |
| Baseline | `internal/executor/baseline/runner_test` uses `httptest` plus in-memory store; performs one GET baseline. |
| Integration | `internal/storage/postgres` when `AXIOM_TEST_DATABASE_URL` is set (runs `dbmigrate.Up` from `AXIOM_TEST_MIGRATIONS_DIR` or repo-root `migrations/`, through `000007_scan_run_orchestration` and earlier). |
| End-to-end | `make e2e-local` (httpbin plumbing) and `make e2e-crapi` (OWASP crAPI + same V1 checks); see **Local Docker end-to-end** below. |

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
| `AXIOM_TEST_MIGRATIONS_DIR` | Path to migrations directory (default: `migrations` relative to the process working directory). |

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

**Goal:** Prove the supported safe V1 path against **local** targets only (no unsolicited scans of third-party APIs).

**Axiom-managed stack** (repository root):

```text
docker info   # must show a healthy server
make e2e-local
```

This runs `scripts/e2e_local.sh`, which:

1. Starts `deploy/e2e/docker-compose.yml` services **`axiom-pg`** (Postgres on `127.0.0.1:54334`, DB `axiom_e2e`, user/password `axiom`) and **`httpbin`** (`mccutchen/go-httpbin` on `127.0.0.1:18080`).
2. Builds `bin/axiom-api-e2e` and listens on `127.0.0.1:8080` with `DATABASE_URL=postgres://axiom:axiom@127.0.0.1:54334/axiom_e2e?sslmode=disable`.
3. Exercises, via `curl` + `jq`: create scan with `base_url` = httpbin, `POST .../specs/openapi` with `testdata/e2e/httpbin-openapi.yaml`, list endpoints, baseline, mutations, list executions, list findings, optional finding + evidence GETs, then a second scan with `POST .../run` (`action: start`) and a second `POST .../run` (`action: resume`) after `findings_complete`.

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

**What is actually exercised:** V1 **GET** and **JSON POST** baseline/mutation paths against crAPI’s reachable operations; **safe** rules under `rules/` (planner-eligible operations only); **diff/matchers** and **finding + evidence_summary** persistence when matchers complete; **read APIs** for executions/findings; **orchestrator** idempotent `resume` after completion. Finding counts vary with rules and responses (automated run observed non-zero findings).

**Not exercised in this harness:** crAPI **authenticated** sessions (no `auth_headers` / JWT setup in the script), browser-only flows, non–safe rule modes, Juice Shop, or coverage guarantees for every path in the spec.

**Teardown crAPI:** from `.cache/crapi/deploy/docker`: `docker compose -f docker-compose.yml down` (destroys crAPI volumes if you add `-v`; only do that when you intend to reset lab data).

**Ports:** crAPI uses **8888** (and upstream services use other host ports such as **8025** for Mailhog). Axiom e2e uses **8080** and **54334**. If **8080** is already taken by another process, set **`AXIOM_HTTP_ADDR`** (and matching **`AXIOM_URL`**) before running the script, or stop the conflicting listener; the script does not auto-pick a free port.

**Juice Shop (secondary):** `docker compose -f deploy/e2e/docker-compose.yml --profile juice up -d` exposes `127.0.0.1:13000`. Prefer browser/app flows upstream; API OpenAPI varies by version—validate imports manually.

**Swagger Petstore:** use only for harmless spec experiments if needed; prefer local httpbin for automation.

**Known limitations:** `e2e-local` does not start crAPI; `e2e-crapi` does not start httpbin. Fixed ports are intentional for reproducibility; resolve conflicts by stopping other listeners or overriding env vars documented above. Orchestration is synchronous and holds the HTTP connection for `start`/`resume`.

## Evidence normalization

When comparing responses, strip or replace fields such as `Date`, `X-Request-Id`, and server-specific tokens. Document normalization rules next to golden files when they are introduced.
