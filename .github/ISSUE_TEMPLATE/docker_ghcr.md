---
name: Docker / GHCR image
about: Pull, manifest, multi-arch, or container runtime issues (not scanner findings—use Bug report)
title: '[dist] '
labels: ''
---

## What failed

- [ ] `docker pull` (HTTP error / unauthorized / wrong arch)
- [ ] Image runs but API unhealthy (migrations, crash loop, port bind)
- [ ] Unexpected arch (expected arm64, got amd64, etc.)
- [ ] Other distribution issue

## Exact reference

- Image reference used (e.g. `ghcr.io/codethor0/axiom-api-scanner:latest`):
- `docker version` (client + server if applicable):
- Host OS and CPU: 

## Minimal repro

1. Command(s) you ran (redact tokens):
2. Full error line or HTTP status (if any):

## Clean-machine check

Did you run the steps in [README — Clean machine validation](https://github.com/codethor0/axiom-api-scanner/blob/main/README.md#clean-machine-validation-ghcr)? **Yes / No** — if no, what differed?

## Optional

`docker manifest inspect ...` output snippet (no secrets).
