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

API **image** smoke (`docker build` + ephemeral Postgres + `GET /v1/rules`):

```text
make docker-api-smoke
```

Full **release-candidate** recipe: `make release-candidate-proof` (see [docs/testing.md](docs/testing.md)). Expected **benchmark** rows per V1 family: [docs/benchmark-results.md](docs/benchmark-results.md). Touching **`Dockerfile`**, **`scripts/docker_api_smoke.sh`**, or **`.github/workflows/container-publish.yml`**: run **`make docker-api-smoke`** before opening a PR when possible; optionally **`make docker-api-smoke-ghcr`** if a published tag exists and you have pull access.

## Reporting issues

- Use GitHub Issues on [codethor0/axiom-api-scanner](https://github.com/codethor0/axiom-api-scanner).
- **Especially useful for RC traction:** **false positives** (noisy or misleading findings), **false negatives** (missed abuse class you expected), **setup friction** (install, Docker, ports, docs gaps), **auth or OpenAPI input coverage** you need but do not see documented, and **Docker/GHCR** pull, manifest, or runtime issues.
- Include: Go version (if you built from source), OS, commit or tag or **image tag** (`v0.1.0-rc.1`, `latest`, `sha-…`), repro steps, expected vs actual behavior, and whether you ran **`make ci-unit`**, **`make e2e-local`**, **`make benchmark-findings-local`**, or **[clean-machine GHCR](https://github.com/codethor0/axiom-api-scanner/blob/main/README.md#clean-machine-validation-ghcr)** when relevant.
- **Security-sensitive** reports: see [SECURITY.md](SECURITY.md).
- **Context:** [docs/faq.md](docs/faq.md), [docs/announcement.md](docs/announcement.md).

## Reporting issues after external validation

If you **did not clone** the repo and only ran the **published image**:

1. Follow the **Clean machine validation** steps in [README.md](README.md#clean-machine-validation-ghcr) (or report exactly where you diverged).
2. Open **[Docker / GHCR image](https://github.com/codethor0/axiom-api-scanner/issues/new?template=docker_ghcr.md)** for pull/manifest/arch/registry/login problems.
3. Open **[Bug report](https://github.com/codethor0/axiom-api-scanner/issues/new?template=bug_report.md)** for **false positives**, **false negatives**, **setup friction** not specific to the registry image, or **auth/spec** gaps — check the feedback-type boxes so maintainers can triage quickly.
4. Open **[Feature request](https://github.com/codethor0/axiom-api-scanner/issues/new?template=feature_request.md)** for product or doc gaps that are not a single broken behavior.

**CI vs local vs image:** three separate proofs — see [README.md](README.md#proof-at-a-glance-three-separate-surfaces) and [docs/testing.md](docs/testing.md#proof-matrix-ci-vs-local-vs-environment).

## Pull requests

- Do not commit prompt logs, agent transcripts, or scratch artifacts.
- Match existing style: formatting, test patterns, and documentation tone.
- Expanding **scanner attack surface** or adding **new detection families** should be a **deliberate** maintainer decision; prefer issues or a short design note for large shifts.
