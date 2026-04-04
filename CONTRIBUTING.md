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

## Issue triage — pick **one** template

Use **one** primary category so labels and first response stay fast. If two apply (e.g. setup friction **and** false positive), pick the **blocking** one first and mention the other in the body.

| Your situation | Open this template | Title prefix (suggested) |
| --- | --- | --- |
| Finding is wrong, noisy, or misleading | [Bug report](https://github.com/codethor0/axiom-api-scanner/issues/new?template=bug_report.md) | `fp:` or `[bug]` |
| Expected abuse class not detected | [Bug report](https://github.com/codethor0/axiom-api-scanner/issues/new?template=bug_report.md) | `fn:` or `[bug]` |
| Install, clone, ports, docs — **cannot** get to a working API | [Bug report](https://github.com/codethor0/axiom-api-scanner/issues/new?template=bug_report.md) | `setup:` |
| Auth scheme, header, or OpenAPI shape **unsupported or undocumented** for your case | [Bug report](https://github.com/codethor0/axiom-api-scanner/issues/new?template=bug_report.md) (coverage gap) or [Feature request](https://github.com/codethor0/axiom-api-scanner/issues/new?template=feature_request.md) if it is a conscious product ask | `auth:` / `openapi:` |
| `docker pull`, manifest, arch mismatch, registry login, image starts but API unhealthy | **[Docker / GHCR image](https://github.com/codethor0/axiom-api-scanner/issues/new?template=docker_ghcr.md)** only | `[dist]` |
| Broader roadmap / integration idea (not one broken behavior) | [Feature request](https://github.com/codethor0/axiom-api-scanner/issues/new?template=feature_request.md) | `[feature]` |

**Do not** use **Bug report** for pure registry/pull problems — use **Docker / GHCR** so distribution issues stay in one lane.

**Proof to attach (minimum):**

| Category | Attach |
| --- | --- |
| False positive | Rule id (`rule_id`), finding id or **redacted** JSON excerpt, one sentence why it is wrong or noisy |
| False negative | V1 family or abuse class you expected, what you ran (API calls or Makefile target), **redacted** path/method or OpenAPI snippet |
| Setup friction | Exact commands, **full** error text, OS/CPU, commit or image tag |
| Auth / input gap | Auth scheme (e.g. bearer, API key header name), **redacted** OpenAPI fragment or request shape |
| GHCR / image | Image ref, `docker version`, host OS/CPU, pull or run error line — see template |

## Reporting issues

- Use GitHub Issues on [codethor0/axiom-api-scanner](https://github.com/codethor0/axiom-api-scanner).
- **Especially useful for RC traction:** **false positives**, **false negatives**, **setup friction**, **auth or OpenAPI input coverage**, and **Docker/GHCR** issues — see the table above.
- Always include: **version** (commit, `v*`, tag, or **`latest`/`sha-*`** image), OS/arch, repro steps, expected vs actual, and **which proof** you ran (`ci-unit`, clean-machine, `e2e-local`, benchmark, etc.).
- **Security-sensitive** reports: see [SECURITY.md](SECURITY.md).
- **Context:** [docs/faq.md](docs/faq.md), [docs/announcement.md](docs/announcement.md).

## Reporting issues after external validation

If you **did not clone** the repo and only ran the **published image**:

1. Follow the **Clean machine validation** steps in [README.md](README.md#clean-machine-validation-ghcr) (or report exactly where you diverged).
2. **Registry or container only:** [Docker / GHCR image](https://github.com/codethor0/axiom-api-scanner/issues/new?template=docker_ghcr.md).
3. **Scanner behavior** after the API works: [Bug report](https://github.com/codethor0/axiom-api-scanner/issues/new?template=bug_report.md) — check **one** primary feedback type.
4. **Roadmap / design ask:** [Feature request](https://github.com/codethor0/axiom-api-scanner/issues/new?template=feature_request.md).

**CI vs runtime:** green **CI** on GitHub is **not** Docker e2e, benchmark, or a GHCR pull. See [README.md](README.md#proof-at-a-glance-three-separate-surfaces) and [docs/testing.md](docs/testing.md#proof-matrix-ci-vs-local-vs-environment).

## Pull requests

- Do not commit prompt logs, agent transcripts, or scratch artifacts.
- Match existing style: formatting, test patterns, and documentation tone.
- Expanding **scanner attack surface** or adding **new detection families** should be a **deliberate** maintainer decision; prefer issues or a short design note for large shifts.
