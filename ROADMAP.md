# Roadmap

Goals are **ordered** and **honest** about current V1 limits. See [docs/comparison.md](docs/comparison.md) for how this scope fits next to broader tools.

## Near term (post release candidate)

- **Tagged releases** and **release notes** per [CHANGELOG.md](CHANGELOG.md).
- Optional **container image** or documented **compose-only** quickstart if maintainers choose to publish one (today: `deploy/e2e/docker-compose.yml` is proof-oriented).
- **Comparative benchmarks** on allowed targets (document methodology; no unverifiable claims).

## Product directions (not committed dates)

- Deeper **auth** and session coverage for real APIs.
- Additional **input formats** or discovery paths where they fit the safety model.
- Stronger **operator UX**: exports, stable CLIs, integrations (without widening blast radius by default).

## Explicit non-goals for “safe V1”

- Ungoverned **fuzzing** or **destructive** payloads as a default.
- **Admin/write surfaces** beyond the existing control plane unless scoped and documented.
- “Beat every feature” of general DAST suites; the wedge is **bounded, evidence-first API abuse checks** on **OpenAPI-first** workflows.

For **release-candidate proof commands**, see [docs/testing.md](docs/testing.md).
