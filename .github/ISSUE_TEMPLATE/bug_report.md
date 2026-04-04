---
name: Bug report
about: Scanner behavior, setup, FP/FN, or auth/spec gaps — not pure docker pull/registry (use Docker/GHCR template)
title: '[bug] '
labels: ''
---

## Primary type (pick one)

- [ ] **False positive** — finding wrong or too noisy
- [ ] **False negative** — expected signal missing
- [ ] **Setup friction** — cannot reach working API from docs/Makefile
- [ ] **Auth or OpenAPI/input coverage gap** — scheme or spec shape blocks you
- [ ] **Other** — API bug not covered above

**Pure `docker pull` / manifest / arch / registry login?** Open **[Docker / GHCR image](https://github.com/codethor0/axiom-api-scanner/issues/new?template=docker_ghcr.md)** instead.

## Attach (minimum — see CONTRIBUTING)

| Type | Paste |
| --- | --- |
| False positive | `rule_id`, `finding_id` or redacted finding JSON, one line why it is wrong |
| False negative | Expected V1 family or class, what you ran, redacted endpoint or spec snippet |
| Setup | Full error text + exact commands |
| Auth / input | Auth scheme + redacted OpenAPI or headers |

## Environment

- Commit / tag / **image tag** (e.g. `sha-…`, `v0.1.0-rc.1`, `latest`):
- Go (`go version`) or **N/A** (image-only):
- OS + CPU arch:
- Docker (`docker version`) if you used Docker:
- Postgres (if relevant):
- `safety_mode`, `allow_full_execution`, `AXIOM_RULES_DIR` if relevant:

## Steps to reproduce

1.
2.

## Expected

## Actual

## Proof you already ran (CI is not runtime proof)

- [ ] **`make ci-unit`** (source only — does not prove GHCR or benchmark)
- [ ] **[Clean machine GHCR](https://github.com/codethor0/axiom-api-scanner/blob/main/README.md#clean-machine-validation-ghcr)** (no clone)
- [ ] **`make docker-api-smoke`** or **`make docker-api-smoke-ghcr`**
- [ ] **`make e2e-local`** and/or **`make benchmark-findings-local`** or **`make release-candidate-proof`**
- [ ] **`go test ./... -count=1`** with `AXIOM_TEST_DATABASE_URL` (storage-related)

## Optional

Logs, redacted responses (no secrets).
