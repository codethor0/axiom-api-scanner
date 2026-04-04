---
name: Bug report
about: Report incorrect scanner/API behavior (not security of Axiom itself—see SECURITY.md)
title: '[bug] '
labels: ''
---

## Environment

- Axiom commit or tag:
- Go version (`go version`):
- OS:
- Postgres version (if relevant):
- `AXIOM_RULES_DIR` / safety_mode / scan context (if relevant):

## Steps to reproduce

1.
2.

## Expected

## Actual

## Proof you already ran (check all that apply)

- [ ] `make ci-unit`
- [ ] `make release-candidate-proof` (or `make e2e-local` / `make benchmark-findings-local`)
- [ ] `go test ./... -count=1` with `AXIOM_TEST_DATABASE_URL` for postgres integration (if storage-related)

## Optional

Logs, redacted API response snippets, rule id and finding id (no secrets).
