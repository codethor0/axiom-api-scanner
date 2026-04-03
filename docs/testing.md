# Testing

## Goals

- Prove correctness of parsers, validation, and planning logic.
- Keep tests deterministic: normalize timestamps, random identifiers, and unstable ordering before golden comparisons.
- Fail CI on regressions in rule loading, OpenAPI extraction, and public HTTP contracts.

## Layers

| Layer | Scope |
| --- | --- |
| Unit | Rule validation, YAML parsing edge cases, OpenAPI extraction helpers. |
| Integration | HTTP handlers with `httptest`, database repositories against ephemeral PostgreSQL (future). |
| End-to-end | Full scan against recorded fixtures with expected findings (future). |

## Fixtures

Store OpenAPI snippets and HTTP transcripts under a dedicated `testdata` tree (to be expanded). Remove volatile headers and dates when diffing responses.

## Running tests

```text
go test ./...
go vet ./...
```

Linting:

```text
make lint
```

## Evidence normalization

When comparing responses, strip or replace fields such as `Date`, `X-Request-Id`, and server-specific tokens. Document normalization rules next to golden files when they are introduced.
