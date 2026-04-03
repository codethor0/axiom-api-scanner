# Development

## Prerequisites

- Go 1.22+
- Optional: `golangci-lint` for local lint parity with CI
- Optional: PostgreSQL 15+ for applying `migrations/` with your migration tool

## Layout

```text
cmd/api          HTTP control plane
cmd/worker       Background execution (skeleton)
internal/api     Routes and handlers
internal/engine  Scan and endpoint models (engine logic to grow here)
internal/findings Finding and evidence models
internal/rules   YAML loading and validation
internal/spec/openapi OpenAPI ingestion
internal/storage Persistence interfaces
migrations       SQL forward and rollback files
rules            Authoritative YAML rule packs (example under rules/builtin)
docs             Documentation
```

## Configuration

| Variable | Meaning |
| --- | --- |
| `AXIOM_HTTP_ADDR` | Listen address (default `:8080`). |
| `AXIOM_RULES_DIR` | Directory scanned for `*.yml` / `*.yaml` rules (default `./rules`). |

Database connection variables will be documented when repositories are implemented.

## Formatting and build

```text
make fmt
make build
make test
```

## Database migrations

Apply `migrations/*.up.sql` using golang-migrate, goose, or an equivalent. Keep forward and rollback pairs in sync. Never edit applied migrations in place; add a new version instead.
