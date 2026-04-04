---
name: Bug report
about: Report incorrect scanner/API behavior (not security of Axiom itself—see SECURITY.md)
title: '[bug] '
labels: ''
---

## Feedback type (check any that apply)

- [ ] False positive (finding looks wrong or unhelpfully noisy)
- [ ] False negative (expected abuse signal not surfaced)
- [ ] Setup friction (install, Docker, ports, docs)
- [ ] Auth or credential / header coverage gap
- [ ] Docker / GHCR (pull, manifest, arch, login — or use the dedicated template)
- [ ] Other incorrect behavior

## Environment

- Axiom commit or tag (or **image tag**, e.g. `latest` / `sha-…` / `v0.1.0-rc.1`):
- Go version (`go version`, if built from source; else N/A):
- OS and CPU arch (e.g. Darwin arm64, `linux/arm64`):
- Docker (`docker version`), if image-related:
- Postgres version (if relevant):
- `AXIOM_RULES_DIR` / safety_mode / scan context (if relevant):

## Steps to reproduce

1.
2.

## Expected

## Actual

## Proof you already ran (check all that apply)

- [ ] `make ci-unit`
- [ ] `make docker-api-smoke` or **`make docker-api-smoke-ghcr`** (if Docker / packaging / image run issue)
- [ ] [README clean-machine GHCR](https://github.com/codethor0/axiom-api-scanner/blob/main/README.md#clean-machine-validation-ghcr) steps (if no clone)
- [ ] `make release-candidate-proof` (or `make e2e-local` / `make benchmark-findings-local`)
- [ ] `go test ./... -count=1` with `AXIOM_TEST_DATABASE_URL` for postgres integration (if storage-related)

## Optional

Logs, redacted API response snippets, rule id and finding id (no secrets).
