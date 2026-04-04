# Axiom API Scanner

Axiom is a safe-by-default, **evidence-first**, **low-blast-radius** API abuse scanner for **OpenAPI-first** workflows and **authorized** testing. It focuses on a **bounded V1** set of families (IDOR path/query swap, mass assignment privilege injection, path normalization bypass, rate limit header rotation)—not generic “scan everything” DAST. Details: [docs/comparison.md](docs/comparison.md).

**Release candidate:** **`v0.1.0-rc.1`** is **published** on GitHub ([release](https://github.com/codethor0/axiom-api-scanner/releases/tag/v0.1.0-rc.1), [CHANGELOG](CHANGELOG.md)). Launch copy and FAQs: [docs/announcement.md](docs/announcement.md), [docs/faq.md](docs/faq.md). **License:** [LICENSE](LICENSE) (MIT).

## First evaluation (about 5–10 minutes)

Pick **one** path; do not assume CI already ran Docker for you.

| Goal | Command | You need |
| --- | --- | --- |
| Fast sanity (no Docker) | `make ci-unit` | Go; from repo root |
| Full scan lifecycle on **fixtures** | `make e2e-local` | Docker, `curl`, `jq`, free ports **54334**, **18080**, **8080** (defaults) |
| V1 **benchmark matrix** on **fixtures** | `make benchmark-findings-local` | Same + port **18081**; run **after** e2e or use `make release-candidate-proof` |
| Everything local (sequential Docker) | `make release-candidate-proof` | Docker, `curl`, `jq`, Go |

**Read next:** what green means in each layer — [docs/testing.md](docs/testing.md#evaluator-quick-path-first-10-minutes) and the **Proof matrix**. **Demo outline:** [docs/demo-script.md](docs/demo-script.md).

## What Axiom is

- A disciplined rule engine with YAML-defined checks, schema validation, and citations.
- A control-plane HTTP API plus a worker entrypoint for asynchronous execution (worker is scaffold-only today). Read APIs return explicit finding fields (`severity`, `rule_declared_confidence`, `assessment_tier`) and list/detail execution routes. See [docs/api.md](docs/api.md).
- **OpenAPI 3.x** ingestion for endpoint discovery (first-class input for V1).

## What Axiom is not

- Not a license to test systems without authorization.
- Not an unrestricted fuzzing or exploit framework.
- Not a replacement for code review, design review, or broader secure SDLC practices.
- Not yet a full “every format, every workflow” DAST replacement (see [docs/comparison.md](docs/comparison.md)).

## Safety model (summary)

Default execution posture is **passive** or **safe**. Destructive or high-impact rules must be labeled, classified, and **disabled unless explicitly enabled**. See [docs/safety-model.md](docs/safety-model.md).

## Quickstart (API on your Postgres)

**Assumptions (no surprises):**

| Need | Why |
| --- | --- |
| **Repository root** as current directory | Migrations and `AXIOM_RULES_DIR` resolve relative to here. |
| **Go** matching `go.mod` | Build the API binary. |
| **PostgreSQL** you are allowed to migrate | The API runs migrations on startup. |
| **jq** (optional) | Examples below pipe JSON through `jq`. |

**Clone and build:**

```text
git clone https://github.com/codethor0/axiom-api-scanner.git
cd axiom-api-scanner
export DATABASE_URL='postgres://user:pass@localhost:5432/axiom?sslmode=disable'
go build -o bin/axiom-api ./cmd/api
AXIOM_HTTP_ADDR=":8080" AXIOM_RULES_DIR="./rules" DATABASE_URL="$DATABASE_URL" ./bin/axiom-api
```

**Create a scan** (returns a real UUID):

```text
curl -s -X POST localhost:8080/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"target_label":"staging","safety_mode":"safe","allow_full_execution":false}' | jq .
```

**List rules** loaded from `./rules`:

```text
curl -s localhost:8080/v1/rules | jq .
```

**Validate OpenAPI** (replace path with your file):

```text
curl -s -X POST localhost:8080/v1/specs/openapi/validate --data-binary @path/to/spec.yaml
```

**Import OpenAPI into a scan** (use `scan_id` from create; body is **raw** OpenAPI YAML or JSON, not a JSON wrapper):

```text
curl -s -X POST "localhost:8080/v1/scans/{scan_id}/specs/openapi" \
  --data-binary @path/to/spec.yaml | jq .
```

**Orchestrated run** after `base_url` and endpoints exist: `POST /v1/scans/{scan_id}/run` with body `{"action":"start"}`. Full control and read paths: [docs/api.md](docs/api.md).

**Repository:** [github.com/codethor0/axiom-api-scanner](https://github.com/codethor0/axiom-api-scanner).

## Reproducible proof (evaluators and release candidates)

**Important:** **CI** proves **`go test`**, **vet**, **lint**, migration layout, and shell **syntax** of proof scripts. It does **not** run **`make e2e-local`** or **`make benchmark-findings-local`**. For the full local story, use the [Proof matrix](docs/testing.md#proof-matrix-ci-vs-local-vs-environment).

**CI** (on GitHub): migration layout, `bash -n` on local proof scripts, `go vet`, `golangci-lint`, `go test ./...` with Postgres. Details: [docs/testing.md](docs/testing.md#ci-vs-local).

**Local Docker** (requires **Docker**, **curl**, **jq**, free default ports **54334**, **18080**, **18081**, **8080** unless you override env vars documented in [docs/testing.md](docs/testing.md)):

```text
make e2e-local
make benchmark-findings-local
```

**One-shot release-candidate recipe** (static checks + unit tests + both Docker flows):

```text
make release-candidate-proof
```

**Postgres integration tests** (optional, recommended before you tag a release): set `AXIOM_TEST_DATABASE_URL` to a **dedicated** database; then `go test ./internal/storage/postgres/... -count=1 -v` or `make ci` — see [docs/testing.md](docs/testing.md).

**Note:** `bash -n` in CI checks **shell syntax only**, not runtime behavior of Docker scripts.

### Expected outputs (quick sanity)

| Command | Success signal |
| --- | --- |
| `make e2e-local` | Final line: `OK: local e2e validation passed (httpbin path + orchestrator smoke).` |
| `make benchmark-findings-local` | Final line: `OK: finding-quality benchmark passed (httpbin + rate stub, four V1 families with honest httpbin no-finding for rate limit).` |
| `make release-candidate-proof` | Ends with `release-candidate-proof: OK (see also CHANGELOG.md and docs/comparison.md).` |

**Finding read** (detail JSON, richer than list rows): [docs/api.md](docs/api.md#get-v1findingsfindingid). **Benchmark matrix:** expected rows per family: [docs/benchmark-results.md](docs/benchmark-results.md).

### Release checklist (maintainers, future tags after `v0.1.0-rc.1`)

1. `main` matches the intended commit; **`make release-candidate-proof`** green on that commit from a clean tree.
2. Optionally: `export AXIOM_TEST_DATABASE_URL=...` and `go test ./internal/storage/postgres/... -count=1 -v` (integration tests).
3. `CHANGELOG.md` section for the new version; GitHub Release text aligned with it.
4. Annotated tag + publish Release when review is complete (**`v0.1.0-rc.1`** is already [published](https://github.com/codethor0/axiom-api-scanner/releases/tag/v0.1.0-rc.1)).

## Continuous integration

Push and pull requests on `main` run GitHub Actions per [.github/workflows/ci.yml](.github/workflows/ci.yml). **Proof matrix** (what runs where): [docs/testing.md](docs/testing.md#proof-matrix-ci-vs-local-vs-environment).

## Documentation

| Document | Purpose |
| --- | --- |
| [docs/comparison.md](docs/comparison.md) | Positioning vs broader tools; V1 families; proof expectations |
| [docs/announcement.md](docs/announcement.md) | RC launch copy; link to published release |
| [docs/demo-script.md](docs/demo-script.md) | Demo or video outline for evaluators |
| [docs/faq.md](docs/faq.md) | Scope, CI vs local proof, feedback pointers |
| [docs/benchmark-results.md](docs/benchmark-results.md) | Reproducible local benchmark; expected outcomes per V1 family |
| [CHANGELOG.md](CHANGELOG.md) | Release candidate and version notes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute and report issues |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [ROADMAP.md](ROADMAP.md) | Near-term and non-goals |
| [docs/architecture.md](docs/architecture.md) | Control plane, engine, evidence, storage |
| [docs/api.md](docs/api.md) | REST API |
| [docs/rule-authoring.md](docs/rule-authoring.md) | Rule DSL |
| [docs/safety-model.md](docs/safety-model.md) | Safety modes |
| [docs/testing.md](docs/testing.md) | Tests and local Docker flows |
| [docs/development.md](docs/development.md) | Local development |

## Optional stacks

- `make e2e-crapi` / `make e2e-crapi-auth` — OWASP crAPI in Docker (heavy); [docs/testing.md](docs/testing.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible use

Only deploy Axiom against systems you own or are explicitly authorized to test. Follow your organization's policies and applicable law.
