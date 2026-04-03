# Development

## Prerequisites

- Go version per repository `go.mod` directive (currently 1.25+)
- PostgreSQL 14+ with the `pgcrypto` extension available (used for `gen_random_uuid()`)
- Optional: `golangci-lint` for local lint parity with CI

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
cmd/api                 HTTP control plane (runs migrations, PostgreSQL pool)
internal/api            HTTP handlers (depends on storage interfaces only)
internal/dbmigrate      Programmatic migrate wrapper
internal/storage        Repository interfaces and sentinel errors
internal/storage/postgres  pgx implementations
migrations              Versioned SQL (up/down pairs)
```

## Testing

Unit and handler tests (no database):

```text
make test
```

PostgreSQL integration test (optional migration and scan lifecycle smoke):

```text
export AXIOM_TEST_DATABASE_URL='postgres://user:pass@localhost:5432/axiom_test?sslmode=disable'
# Optional if not running from repo root:
export AXIOM_TEST_MIGRATIONS_DIR=/absolute/path/to/migrations
make test-integration
```

When `AXIOM_TEST_DATABASE_URL` is unset, the integration test is skipped.

## Formatting and build

```text
make fmt
make build
```
