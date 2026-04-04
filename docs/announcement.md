# Release announcement copy (v0.1.0-rc.1)

Use or adapt the text below for blog posts, social posts, or team announcements. Keep the **narrow positioning**; do not imply parity with full DAST suites.

## Published artifact

- **Tag:** `v0.1.0-rc.1`
- **GitHub Release:** https://github.com/codethor0/axiom-api-scanner/releases/tag/v0.1.0-rc.1
- **Repository:** https://github.com/codethor0/axiom-api-scanner

## Short announcement (about 120 words)

Axiom API Scanner **`v0.1.0-rc.1`** is a public **release candidate** for teams that want **evidence-first, low-blast-radius** checks on **OpenAPI-described** HTTP APIs under **authorized** testing.

It is **not** a “scan the whole internet” tool. V1 focuses on four bounded families: **IDOR path/query swap**, **mass assignment privilege injection**, **path normalization bypass**, and **rate limit header rotation**, with stored findings and explicit tiers for operators.

CI on the tagged commit runs **vet, lint, and full `go test`** with Postgres. **Docker-backed** end-to-end and benchmark recipes stay **local** by design; see the README and [docs/testing.md](testing.md) for `make e2e-local`, `make benchmark-findings-local`, and `make release-candidate-proof`.

We want **real feedback** on false positives, false negatives, setup friction, and gaps in **auth or spec coverage**—see [CONTRIBUTING.md](../CONTRIBUTING.md) and the issue templates.

## Even shorter (one paragraph)

**Axiom `v0.1.0-rc.1`** is an OpenAPI-first, safe-by-default API abuse **RC** with a small V1 rule surface and honest proof story (CI plus documented local Docker flows). Release: https://github.com/codethor0/axiom-api-scanner/releases/tag/v0.1.0-rc.1 — try the README quickstart and `make ci-unit` or `make release-candidate-proof`; we welcome structured feedback via GitHub Issues.

## Supporting docs

- [comparison.md](comparison.md) — category positioning and gaps
- [benchmark-results.md](benchmark-results.md) — what the local benchmark proves
- [faq.md](faq.md) — common questions
- [demo-script.md](demo-script.md) — walkthrough outline
