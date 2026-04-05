<p align="center">
  <img src="docs/assets/axiom-api-scanner-logo.png" alt="Axiom API Scanner logo" width="320" />
</p>

# Axiom API Scanner

[![CI](https://github.com/codethor0/axiom-api-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/codethor0/axiom-api-scanner/actions/workflows/ci.yml)
[![Container Publish](https://github.com/codethor0/axiom-api-scanner/actions/workflows/container-publish.yml/badge.svg)](https://github.com/codethor0/axiom-api-scanner/actions/workflows/container-publish.yml)
[![Release](https://img.shields.io/github/v/release/codethor0/axiom-api-scanner?display_name=tag)](https://github.com/codethor0/axiom-api-scanner/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/codethor0/axiom-api-scanner/blob/main/LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/codethor0/axiom-api-scanner)](https://github.com/codethor0/axiom-api-scanner/blob/main/go.mod)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fcodethor0%2Faxiom--api--scanner-green)](https://github.com/codethor0/axiom-api-scanner/pkgs/container/axiom-api-scanner)

Axiom is a safe-by-default, evidence-first, low-blast-radius API abuse scanner for OpenAPI-first workflows and authorized testing.

It focuses on a bounded V1 set of families:
- IDOR path/query swap
- mass assignment privilege injection
- path normalization bypass
- rate limit header rotation

It is not generic "scan everything" DAST. Details: [docs/comparison.md](docs/comparison.md).

**Release candidate:** [`v0.1.0-rc.1`](https://github.com/codethor0/axiom-api-scanner/releases/tag/v0.1.0-rc.1)  
**Launch notes:** [docs/announcement.md](docs/announcement.md)  
**FAQ:** [docs/faq.md](docs/faq.md)  
**License:** [MIT](LICENSE)

## Proof at a glance (three separate surfaces)

These are **independent**. Trust **all three** only if each one matches what you need; do not treat CI green as proof that a **pulled** image or **your** target behaved.

| Surface | You need | What it demonstrates | Where |
| --- | --- | --- | --- |
| **CI proof** | Nothing locally | Migration layout, `go vet`, `golangci-lint`, `go test ./...` with Postgres in Actions, `bash -n` on proof scripts — **not** Docker e2e/benchmark or a real registry pull | [`.github/workflows/ci.yml`](.github/workflows/ci.yml), [docs/testing.md](docs/testing.md#proof-matrix-ci-vs-local-vs-environment) |
| **Local source proof** | Git clone, Go, Docker (for full recipe) | API + fixtures: `make e2e-local`, `make benchmark-findings-local`, or **`make release-candidate-proof`** | [docs/testing.md](docs/testing.md), [docs/benchmark-results.md](docs/benchmark-results.md) |
| **GHCR pull/run proof** | Docker + **curl** only (no clone) | The **published** API image boots against **your** Postgres and serves **`GET /v1/rules`** | [Clean machine validation](#clean-machine-validation-ghcr) below; workflow: [`.github/workflows/container-publish.yml`](.github/workflows/container-publish.yml) |

**Outsider path (shortest):** pull image, start Postgres on a Docker network, run the container with `DATABASE_URL`, then **`curl -sf http://127.0.0.1:8080/v1/rules`**. Full copy-paste: [Clean machine validation](#clean-machine-validation-ghcr).

## Validate, then report (two outsider paths)

**CI on GitHub** shows **`go test`**, lint, and migration checks only — it does **not** run the benchmark, e2e stack, or your **`docker pull`**. For **runtime** confidence, use **A** or **B** below, then **C** if something is wrong.

| Step | **A — GHCR (no clone)** | **B — Source (clone)** |
| --- | --- | --- |
| **Validate** | [Clean machine validation](#clean-machine-validation-ghcr): pull image, Postgres, **`curl /v1/rules`** | `git clone` → `make release-candidate-proof` (or `make e2e-local` then `make benchmark-findings-local`) — [docs/testing.md](docs/testing.md#proof-matrix-ci-vs-local-vs-environment) |
| **Proves** | Published image boots and serves the API | Fixtures + V1 benchmark matrix match [docs/benchmark-results.md](docs/benchmark-results.md) |

**C — File the right issue:** [CONTRIBUTING — Issue triage](CONTRIBUTING.md#issue-triage--pick-one-template) (false positive, false negative, setup, auth/spec, or **Docker/GHCR** only). Shortest routing: registry problems → **Docker / GHCR** template; scanner behavior → **Bug report**.

## First evaluation (about 5–10 minutes)

Pick **one** path; do not assume CI already ran Docker for you.

| Goal | Command | You need |
| --- | --- | --- |
| Fast sanity (no Docker) | `make ci-unit` | Go; from repo root |
| API from **GHCR** (no local build) | `docker pull ghcr.io/codethor0/axiom-api-scanner:latest` then [GHCR run](#quickstart-docker-from-ghcr) | Docker; **`DATABASE_URL`**; package must be **public** or you must `docker login ghcr.io` |
| **Clean machine** smoke (pull, Postgres, **`GET /v1/rules`**) | [Clean machine validation](#clean-machine-validation-ghcr) | Docker + **curl** only (no clone required) |
| API in **Docker** + Postgres you supply | `make docker-build-api` then `make docker-run-api` | Docker; **`DATABASE_URL`** (see [Quickstart (Docker)](#quickstart-docker) below) |
| Prove image boots (`GET /v1/rules`) | `make docker-api-smoke` | Docker + **curl** (ephemeral Postgres + cleanup) |
| Full scan lifecycle on **fixtures** | `make e2e-local` | Docker, `curl`, `jq`, free ports **54334**, **18080**, **8080** (defaults) |
| V1 **benchmark matrix** on **fixtures** | `make benchmark-findings-local` | Same + port **18081**; run **after** e2e or use `make release-candidate-proof` |
| Full local proof (sequential Docker) | `make release-candidate-proof` | Docker, `curl`, `jq`, Go |

**Read next:** what green means in each layer — [docs/testing.md](docs/testing.md#evaluator-quick-path-first-10-minutes) and the **Proof matrix**. **Demo outline:** [docs/demo-script.md](docs/demo-script.md).

**Distribution:** prebuilt **API** images are published to **GHCR** when [`.github/workflows/container-publish.yml`](.github/workflows/container-publish.yml) runs (push to **`main`**, **`v*`** tags, or manual **workflow_dispatch**). See [Quickstart (Docker from GHCR)](#quickstart-docker-from-ghcr). You can still build from the [`Dockerfile`](Dockerfile) if you prefer.

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

## Quickstart (Docker)

Build the control-plane API image from the repo root (default tag **`axiom-api-scanner:local`**; override with **`AXIOM_IMAGE=...`**):

```text
make docker-build-api
```

Run against a Postgres you can reach from the container (**`DATABASE_URL`** must include a host the container sees, e.g. `host.docker.internal` on Docker Desktop, or a service name on a user-defined network). Example with a disposable Postgres on a Docker network:

```text
docker network create axiom-eval
docker run -d --name axiom-eval-pg --network axiom-eval \
  -e POSTGRES_PASSWORD=axiom -e POSTGRES_USER=axiom -e POSTGRES_DB=axiom \
  postgres:16-alpine
export DATABASE_URL='postgres://axiom:axiom@axiom-eval-pg:5432/axiom?sslmode=disable'
docker run --rm --network axiom-eval -p 8080:8080 \
  -e DATABASE_URL="$DATABASE_URL" \
  axiom-api-scanner:local
```

Then `curl -s localhost:8080/v1/rules` should return JSON. Stop containers when done.

**Makefile shortcut** (same requirement: set `DATABASE_URL` for a reachable Postgres):

```text
export DATABASE_URL='postgres://...'
make docker-run-api
```

Optional: **`AXIOM_HTTP_PUBLISH=3000:8080`** maps host port **3000** to the API. No secrets belong in the image; pass **`DATABASE_URL`** (and optional **`AXIOM_HTTP_ADDR`**) only at **`docker run`**.

## Quickstart (Docker from GHCR)

**Image repository:** `ghcr.io/codethor0/axiom-api-scanner`

**Platforms:** published manifests include **`linux/amd64`** and **`linux/arm64`** (multi-arch index). Apple Silicon and most ARM Linux hosts can **`docker pull`** without **`--platform`**. Tags produced **before** multi-arch landed may be **amd64-only**; use **`docker pull --platform linux/amd64 ...`** until you pull a newer **`latest`**. See [docs/faq.md](docs/faq.md#what-cpu-architectures-does-the-ghcr-image-support).

**Typical tags** (see [Tag scheme](docs/testing.md#ghcr-tag-scheme) in testing docs):

| Tag | When it appears |
| --- | --- |
| **`latest`** | Latest successful publish from **`main`** |
| **`sha-<short>`** | Same push as **`latest`**, Git commit SHA |
| **`v0.1.0-rc.1`** (example) | Git tag **`v*`** (e.g. release candidate) |

**Pull** (use a pinned tag in production when you can):

```text
docker pull ghcr.io/codethor0/axiom-api-scanner:latest
# or: docker pull ghcr.io/codethor0/axiom-api-scanner:v0.1.0-rc.1
```

**Visibility:** the GitHub **Packages** entry for this image may default to **private**. Repository maintainers should set the package to **public** if anonymous pulls are desired; otherwise run `docker login ghcr.io` (PAT with `read:packages` or appropriate SSO).

**Run** (same contract as local build: bundled **`migrations/`** and **`rules/`**, **no** Postgres inside the image):

```text
docker network create axiom-eval
docker run -d --name axiom-eval-pg --network axiom-eval \
  -e POSTGRES_PASSWORD=axiom -e POSTGRES_USER=axiom -e POSTGRES_DB=axiom \
  postgres:16-alpine
export DATABASE_URL='postgres://axiom:axiom@axiom-eval-pg:5432/axiom?sslmode=disable'
docker run --rm --network axiom-eval -p 8080:8080 \
  -e DATABASE_URL="$DATABASE_URL" \
  ghcr.io/codethor0/axiom-api-scanner:latest
```

**Makefile:** `make docker-pull-ghcr` / `make docker-run-ghcr` (uses **`AXIOM_GHCR_IMAGE`**, default **`...:latest`**).

**Narrow smoke on a pulled GHCR image** (skips `docker build`; **`docker pull` must succeed**):

```text
make docker-api-smoke-ghcr
```

Use **`AXIOM_GHCR_IMAGE=...`** to pin a tag. If the package is not published or is private and you are not logged in, use **`make docker-api-smoke`** (build from source) or the **`curl`** flow above. Details: [docs/testing.md](docs/testing.md#docker-api-image-packaging).

## Clean machine validation (GHCR)

Shortest **external** check that the **published API image** runs (no git clone; assumes **Docker** and **curl**; **Postgres** via a throwaway container):

1. **`docker pull ghcr.io/codethor0/axiom-api-scanner:latest`** (or a pinned **`v*`** / **`sha-*`** tag).
2. **`docker network create axiom-clean`** (skip if it already exists; pick another name if needed).
3. Start Postgres on that network (passwords are **example-only**):

   ```text
   docker run -d --name axiom-clean-pg --network axiom-clean \
     -e POSTGRES_PASSWORD=axiom -e POSTGRES_USER=axiom -e POSTGRES_DB=axiom \
     postgres:16-alpine
   ```

4. Run the API (wait a few seconds if Postgres just started):

   ```text
   docker run --rm --network axiom-clean -p 8080:8080 \
     -e DATABASE_URL='postgres://axiom:axiom@axiom-clean-pg:5432/axiom?sslmode=disable' \
     ghcr.io/codethor0/axiom-api-scanner:latest
   ```

5. In another terminal: **`curl -sf http://127.0.0.1:8080/v1/rules`** — expect **HTTP** **200** and JSON.

**Contains:** **`cmd/api`** binary, **`/app/migrations`**, **`/app/rules`**. **Does not contain:** Postgres, scan fixtures, or the **e2e**/benchmark stacks. Remove containers/network when finished.

### After clean-machine validation

- **Pull, manifest, arch, login, container health:** **[Docker / GHCR image](https://github.com/codethor0/axiom-api-scanner/issues/new?template=docker_ghcr.md)** — not Bug report.
- **API works but findings or behavior look wrong:** **[Bug report](https://github.com/codethor0/axiom-api-scanner/issues/new?template=bug_report.md)** — pick **one** primary feedback type; attach rule/finding ids or redacted JSON per [CONTRIBUTING](CONTRIBUTING.md#issue-triage--pick-one-template).

Include **image tag**, **host OS/CPU**, **`docker version`**, `DATABASE_URL` **shape** only (no passwords), and exact **`curl`/HTTP** error for distribution issues.

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

Push and pull requests on `main` run [.github/workflows/ci.yml](.github/workflows/ci.yml). Pushes to **`main`** and version tags **`v*`** also run [.github/workflows/container-publish.yml](.github/workflows/container-publish.yml) (GHCR API image). **Proof matrix** (what runs where): [docs/testing.md](docs/testing.md#proof-matrix-ci-vs-local-vs-environment).

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
| [docs/testing.md](docs/testing.md) | Tests, Docker image smoke, local Docker flows |
| [Dockerfile](Dockerfile) | Multi-stage build for `cmd/api` (rules + migrations in image) |
| [docs/development.md](docs/development.md) | Local development |

## Optional stacks

- `make e2e-crapi` / `make e2e-crapi-auth` — OWASP crAPI in Docker (heavy); [docs/testing.md](docs/testing.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible use

Only deploy Axiom against systems you own or are explicitly authorized to test. Follow your organization's policies and applicable law.
