# Changelog

All notable changes are documented here. The format is loose; versions match git tags when published.

## [0.1.0-rc.1] - 2026-04-04

**Release candidate** for the **safe V1** surface. Not a feature expansion release; it captures a reproducible, documented state for public evaluation.

### Positioning

- **Category goal:** evidence-driven, **OpenAPI-first**, **safe-by-default** API abuse checks for a **small set of V1 families** (see [docs/comparison.md](docs/comparison.md)).
- **Not claimed:** parity with full enterprise DAST or every API input format.

### Proof expectations at this tag

| Layer | How to verify |
| --- | --- |
| CI (GitHub Actions) | Migration layout, `bash -n` on local proof scripts, `go vet`, `golangci-lint`, `go test ./...` with Postgres service |
| Local Docker | `make e2e-local`, `make benchmark-findings-local` |
| Full local RC recipe | `make release-candidate-proof` |

### Documentation

- README quickstart and reproducible paths.
- OSS pack: `CONTRIBUTING.md`, `SECURITY.md`, `ROADMAP.md`, `LICENSE`, this changelog.
- Comparative positioning: `docs/comparison.md`.

### Notes

- **Worker** binary remains a scaffold; orchestration relevant to V1 runs in-process as documented.
- `bench_*` harness strings in local benchmark output are **fixture/proof** aids; API findings use normal finding fields (see [docs/api.md](docs/api.md)).

Maintainers: after review, create git tag **`v0.1.0-rc.1`** and publish a GitHub Release pointing at this changelog section.
