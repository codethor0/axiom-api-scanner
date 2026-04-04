# Contributing

## What this project is

A safe-by-default API scanner with a **control-plane HTTP API**, **OpenAPI 3.x** ingestion, and a **bounded V1** mutation and finding pipeline (see [README.md](README.md), [docs/architecture.md](docs/architecture.md)).

## What it is not (yet)

- Not a general-purpose replacement for full DAST suites (see [docs/comparison.md](docs/comparison.md)).
- Not a fuzzer or unrestricted exploit framework.
- Not authorized to target systems without permission.

## Before you start

1. Read [docs/safety-model.md](docs/safety-model.md) and [docs/testing.md](docs/testing.md) (especially the **Proof matrix**).
2. Run from the **repository root** so `./migrations`, `./rules`, and scripts resolve.
3. Use **small, reviewable** changes. Behavior changes should include **tests** and **relevant docs** in the same change.

## Development checks

```text
make ci-unit
```

With Postgres for integration tests (same idea as CI):

```text
export AXIOM_TEST_DATABASE_URL='postgres://USER:PASS@HOST:PORT/DB?sslmode=disable'
make ci
```

Docker-backed flows (require Docker, `curl`, `jq`):

```text
make e2e-local
make benchmark-findings-local
```

Full **release-candidate** recipe: `make release-candidate-proof` (see [docs/testing.md](docs/testing.md)).

## Reporting issues

- Use GitHub Issues on [codethor0/axiom-api-scanner](https://github.com/codethor0/axiom-api-scanner).
- Include: Go version, OS, `go.mod` version, repro steps, expected vs actual behavior, and whether you ran **`make ci-unit`** / **`make e2e-local`** when relevant.
- **Security-sensitive** reports: see [SECURITY.md](SECURITY.md).

## Pull requests

- Do not commit prompt logs, agent transcripts, or scratch artifacts.
- Match existing style: formatting, test patterns, and documentation tone.
- Expanding **scanner attack surface** or adding **new detection families** should be a **deliberate** maintainer decision; prefer issues or a short design note for large shifts.
