---
name: Feature request
about: Suggest product or docs improvements (large scope may be deferred—see ROADMAP.md)
title: '[feature] '
labels: ''
---

**False positive, false negative, or “API returns wrong data”?** Use **[Bug report](https://github.com/codethor0/axiom-api-scanner/issues/new?template=bug_report.md)**. **`docker pull` / image only?** Use **[Docker / GHCR](https://github.com/codethor0/axiom-api-scanner/issues/new?template=docker_ghcr.md)**. Routing table: [CONTRIBUTING — Issue triage](https://github.com/codethor0/axiom-api-scanner/blob/main/CONTRIBUTING.md#issue-triage--pick-one-template).

## Problem / use case

What workflow or integration is hard today? If this is **coverage** (auth scheme, spec format, deployment shape), say so explicitly.

## Proposal

Keep scope concrete. This project optimizes for **OpenAPI-first**, **safe V1** abuse checks—not generic “everything DAST.”

**Traction-friendly signals:** missing **auth scheme** (API key, OAuth, mTLS), **OpenAPI version or extension** you need, **target environment** friction (CI, cloud DB, **Docker/GHCR** publish expectations), or **operator UX** on read APIs.

## Non-goals for this request (if any)

What should maintainers explicitly not do in the same change?

## Docs / proof

Would this require updates to `docs/comparison.md`, `docs/api.md`, or `docs/testing.md`?
