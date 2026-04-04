# Development

## Prerequisites

- Go version per repository `go.mod` directive (currently 1.25+)
- PostgreSQL 14+ with the `pgcrypto` extension available (used for `gen_random_uuid()`)
- `golangci-lint` (v2.x, compatible with [.golangci.yml](../.golangci.yml)) for the same lint gate as CI

## Environment variables

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Required by `cmd/api`. Example: `postgres://user:pass@localhost:5432/axiom?sslmode=disable` |
| `AXIOM_MIGRATIONS_DIR` | Directory containing SQL migrations (default: `migrations` relative to the process working directory) |
| `AXIOM_RULES_DIR` | Rule YAML root (default: `rules`) |
| `AXIOM_HTTP_ADDR` | Listen address (default: `:8080`) |

## Schema migrations

The project standardizes on **[golang-migrate](https://github.com/golang-migrate/migrate)** with the **postgres** driver and **file** source.

Two supported workflows:

### 1. Automatic (API startup)

`cmd/api` runs `internal/dbmigrate.Up` against `AXIOM_MIGRATIONS_DIR` before accepting traffic. Run the API from the repository root (or set `AXIOM_MIGRATIONS_DIR` to an absolute path) so `file://` resolution finds the SQL files.

### 2. CLI via Makefile (same tool, explicit operator control)

From the repository root:

```text
export DATABASE_URL='postgres://user:pass@localhost:5432/axiom?sslmode=disable'
make migrate-up
```

Roll back one version:

```text
make migrate-down
```

The Makefile invokes:

```text
go run -tags postgres github.com/golang-migrate/migrate/v4/cmd/migrate@v4.17.1 -path migrations -database "$DATABASE_URL" up
```

Keep this version aligned with `github.com/golang-migrate/migrate/v4` in `go.mod`.

## Layout

```text
cmd/api                    HTTP control plane (migrations, pool, baseline + mutation runners)
internal/api               Handlers
internal/dbmigrate         golang-migrate wrapper
internal/engine            Domain types (scan, scan_endpoint, execution_record)
internal/spec/openapi      OpenAPI extraction
internal/plan/v1           V1 eligibility planner
internal/mutate            Deterministic mutation candidates
internal/pathutil          Path template helpers
internal/executil          Scope, body normalization, header redaction for evidence
internal/diff/v1           Baseline vs mutated matcher evaluation
internal/executor/baseline Baseline HTTP runner
internal/executor/mutation Mutation HTTP runner + request builder
internal/storage           Repository interfaces
internal/storage/postgres  pgx store
migrations                 SQL versions
rules                      YAML rule packs
```

## Baseline execution notes

- Configure `base_url` (create or `PATCH`) before `POST .../executions/baseline`.
- Import OpenAPI for the scan first so `scan_endpoints` rows exist.
- Only GET and POST-with-JSON-body endpoints run; others appear in `skipped_detail`.
- Baseline does not increase scan lifecycle `status`; use control routes for that separately.

## Mutation execution notes

- Run baseline successfully before `POST .../executions/mutations` (`baseline_must_succeed_first` otherwise).
- Mutations are sequential; scope and method support match baseline (GET + JSON POST).
- Findings require rules in `AXIOM_RULES_DIR` with matchers the diff engine supports; incomplete evaluation skips finding creation. Persisted findings include `evidence_summary` JSON and assessed confidence/status tiers.
- Use `GET .../executions` and `GET .../executions/{id}` to inspect exchanges; sensitive headers are redacted in stored metadata.

## Testing

**CI parity (recommended before a PR):** from the repository root, with a dedicated Postgres database URL:

```text
export AXIOM_TEST_DATABASE_URL='postgres://user:pass@localhost:5432/axiom_test?sslmode=disable'
make ci
```

That runs `./scripts/check_migrations.sh`, `go vet ./...`, `golangci-lint run`, and `go test ./... -count=1` with `AXIOM_TEST_MIGRATIONS_DIR` set to the repo `migrations/` folder (same ordering as `.github/workflows/ci.yml`).

**Without Postgres:** `make ci-unit` runs the same gates except it does not require `AXIOM_TEST_DATABASE_URL`; postgres integration tests skip.

**Ad hoc unit tests:**

```text
make test
```

**PostgreSQL integration only** (`internal/storage/postgres`, see [testing.md](testing.md)):

```text
export AXIOM_TEST_DATABASE_URL='postgres://user:pass@localhost:5432/axiom_test?sslmode=disable'
make test-integration
```

When `AXIOM_TEST_DATABASE_URL` is unset, `go test ./...` skips those tests; `make ci` fails fast if the variable is unset so local runs match the Actions job.

Optional GitHub Actions YAML check (same validator many teams run locally; needs network the first time):

```text
make workflow-lint
```

## Local end-to-end validation (Docker)

For a full V1 smoke against **local** httpbin + Postgres (no third-party targets), use:

```text
make e2e-local
```

For the same checks against **local OWASP crAPI** (clone + upstream compose + Axiom):

```text
make e2e-crapi
make e2e-crapi-auth   # adds signup/login JWT + second scan with auth_headers
```

Details and teardown: [testing.md](testing.md#local-docker-end-to-end-v1).

**Credential storage:** scan `auth_headers` are stored in PostgreSQL as part of scan configuration so the API can replay authenticated baselines and mutations. `execution_records` persist **redacted** request and response header maps for known sensitive names (for example `Authorization`, `Cookie`, `X-Api-Key`); values are not stored in plaintext in those artifacts.

## Formatting and build

```text
make fmt
make build
```
