# Axiom API Scanner

Axiom is a safe-by-default, evidence-driven API scanner for **authorized** security testing. It targets API logic flaws (for example broken object level authorization, mass assignment, selected authorization bypass patterns, and controlled rate-limit checks) with reproducible proof artifacts, bounded scope, and explicit safety modes.

## What Axiom is

- A disciplined rule engine with YAML-defined checks, schema validation, and citations.
- A control-plane HTTP API plus a worker entrypoint for asynchronous execution (worker is scaffold-only today). Read APIs return explicit finding fields (`severity`, `rule_declared_confidence`, `assessment_tier`) and nested execution snapshots for list/detail execution routes—see [docs/api.md](docs/api.md).
- An OpenAPI 3.x ingestion path for endpoint discovery (first-class input format for V1).

## What Axiom is not

- Not a license to test systems without authorization.
- Not an unrestricted fuzzing or exploit framework.
- Not a replacement for code review, design review, or broader secure SDLC practices.

## Safety model (summary)

Default execution posture is **passive** or **safe**. Destructive or high-impact rules must be labeled, classified, and **disabled unless explicitly enabled**. Scope enforcement, audit logging, and evidence capture are core requirements, not optional plugins. See [docs/safety-model.md](docs/safety-model.md).

## Quickstart

Requirements: Go as specified in `go.mod` and a PostgreSQL database.

Repository: [github.com/codethor0/axiom-api-scanner](https://github.com/codethor0/axiom-api-scanner) (`git clone https://github.com/codethor0/axiom-api-scanner.git`).

From the repository root (so migrations resolve), set `DATABASE_URL` and start the API (migrations run on startup):

```text
export DATABASE_URL='postgres://user:pass@localhost:5432/axiom?sslmode=disable'
go build -o bin/axiom-api ./cmd/api
AXIOM_HTTP_ADDR=":8080" AXIOM_RULES_DIR="./rules" DATABASE_URL="$DATABASE_URL" ./bin/axiom-api
```

Create a scan (returns a real UUID and database timestamps):

```text
curl -s -X POST localhost:8080/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"target_label":"staging","safety_mode":"safe","allow_full_execution":false}' | jq .
```

List loaded rules (from `AXIOM_RULES_DIR`):

```text
curl -s localhost:8080/v1/rules | jq .
```

Validate an OpenAPI document:

```text
curl -s -X POST localhost:8080/v1/specs/openapi/validate --data-binary @spec.yaml
```

Import endpoints from OpenAPI (validation + extraction):

```text
curl -s -X POST localhost:8080/v1/specs/openapi/import --data-binary @spec.yaml | jq .
```

After a scan has imported endpoints and a `base_url`, you can run baseline and mutations in one synchronous orchestrated pass with `POST /v1/scans/{scan_id}/run` and body `{"action":"start"}` (details and resume/cancel in [docs/api.md](docs/api.md)).

**Continuous integration:** push and pull requests on `main` run GitHub Actions: migration layout checks, `go vet`, `golangci-lint`, and `go test ./...` against a PostgreSQL 16 service (sets `AXIOM_TEST_DATABASE_URL` so `internal/storage/postgres` integration tests run). See [docs/testing.md](docs/testing.md#ci-vs-local).

**Local validation:** with Docker available, run from the **repository root** so `./rules`, `./migrations`, and `deploy/e2e/docker-compose.yml` resolve.

- `make e2e-local` — Postgres + httpbin, ad-hoc baseline/mutations, findings read paths, orchestrator smoke (**[docs/testing.md](docs/testing.md#local-docker-end-to-end-v1)**).
- `make benchmark-findings-local` — same stack plus a **local nginx** rate-limit stub; asserts builtin rule tiers, **`interpretation_hints`**, and harness-only **`bench_*`** codes (see [docs/testing.md](docs/testing.md#finding-quality-benchmark-local-httpbin-and-nginx-rate-stub)). Default bind ports **54334** (Postgres), **18080** (httpbin), **18081** (stub), **8080** (API); set **`AXIOM_HTTP_ADDR`**, **`AXIOM_URL`**, **`HTTPBIN_URL`**, **`RATE_STUB_URL`**, **`DATABASE_URL`** if yours conflict. **GitHub Actions does not run** these Docker scripts (CI is `go vet` / lint / `go test` only per [.github/workflows/ci.yml](.github/workflows/ci.yml)).

`make e2e-crapi` runs the same class of checks against **[OWASP crAPI](https://github.com/OWASP/crAPI)** in Docker (clone under `.cache/crapi`). `make e2e-crapi-auth` adds an API-only signup/login JWT and re-runs baseline/mutations with `auth_headers`. See [docs/testing.md](docs/testing.md).

## Documentation

| Document | Purpose |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Control plane, engine, evidence, storage |
| [docs/rule-authoring.md](docs/rule-authoring.md) | Rule DSL and examples |
| [docs/safety-model.md](docs/safety-model.md) | Safety modes and enforcement |
| [docs/testing.md](docs/testing.md) | Test strategy |
| [docs/development.md](docs/development.md) | Local development workflow |
| [docs/api.md](docs/api.md) | REST API overview |

## Roadmap (V1 focus)

- Planner and executor for authenticated baseline and mutated requests.
- Diff and finding pipeline with required evidence fields.
- Rule packs: IDOR path and query swaps, mass assignment, selected 403 or path normalization bypass checks, controlled rate-limit header rotation after baseline detection.

## Contributing

Use small, reviewable changes. Every behavior change should include tests and documentation updates in the same change. Do not commit prompt transcripts or scratch artifacts.

## Responsible use

Only deploy Axiom against systems you own or are explicitly authorized to test. Follow your organization's policies and applicable law.
