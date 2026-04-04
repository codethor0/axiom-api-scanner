---
name: Docker / GHCR image
about: Pull, manifest, multi-arch, registry — not FP/FN on findings (use Bug report)
title: '[dist] '
labels: ''
---

## Primary failure (pick one)

- [ ] **`docker pull`** (HTTP / unauthorized / denied / wrong arch)
- [ ] **Container runs** but API fails (migrations, crash, port)
- [ ] **Wrong architecture** vs expected
- [ ] **Other** distribution

## Attach (minimum)

- Full **`docker pull`** or **`docker run`** error line(s) (redact tokens)
- Image ref exactly as typed (e.g. `ghcr.io/codethor0/axiom-api-scanner:latest`)
- `docker version` + host OS + CPU

## Exact reference

- Image reference:
- `docker version`:
- Host OS and CPU:

## Minimal repro

1. Command(s) (redact secrets):
2. Output:

## Clean-machine check

Followed [README — Clean machine validation](https://github.com/codethor0/axiom-api-scanner/blob/main/README.md#clean-machine-validation-ghcr)? **Yes / No** — if no, what differed?

## Optional

`docker manifest inspect ...` snippet (no secrets).

**Findings wrong after the image runs?** Use [Bug report](https://github.com/codethor0/axiom-api-scanner/issues/new?template=bug_report.md).
