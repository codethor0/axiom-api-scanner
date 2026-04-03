# Architecture

This document describes the intended shape of Axiom at V1. The repository scaffold implements a subset: models, rule loading, OpenAPI endpoint extraction, SQL migrations, and a stub HTTP API.

## Components

### Control plane (`cmd/api`, `internal/api`)

The HTTP API creates scans, transitions scan state, lists findings, serves evidence pointers, lists and validates rules, and accepts OpenAPI documents for validation and import. Long-running work should move to the worker; the API remains the orchestration surface.

### Worker (`cmd/worker`)

Executes scan plans: baseline requests, mutations, diffing, and evidence persistence. The current binary is a graceful-shutdown skeleton until the engine is connected.

### Engine (`internal/engine`)

Domain types for scans and endpoints. Future packages will host the planner (select endpoints and rules under safety and scope constraints), executor (HTTP client with audit trail), mutator pipeline, and diff engine.

### Rules (`internal/rules`, `rules/`)

YAML rule definitions are loaded from disk, parsed, and validated before execution. The DSL is a product surface: backward compatibility and schema versioning will matter as rules evolve.

### OpenAPI (`internal/spec/openapi`)

Loads OpenAPI 3.x specifications, validates them, and extracts a flat list of HTTP operations for planning.

### Findings (`internal/findings`)

Finding and evidence artifact models. A valid finding must remain reproducible from stored evidence (baseline and mutated requests and responses, diff summary, rule identifier).

### Storage (`internal/storage`, `migrations/`)

PostgreSQL holds scan and finding metadata. Evidence payloads are stored behind the `EvidenceStore` interface (filesystem or object storage in production). Migrations use reversible SQL files; apply them with your chosen migration runner.

## Request flow (target)

1. Import OpenAPI and validate scope.
2. Build a plan: endpoints x rules filtered by safety mode, prerequisites, and tags.
3. For each planned step, record baseline traffic, apply mutations, record mutated traffic, compute diff, evaluate matchers.
4. Persist evidence first, then finding rows that reference evidence locations.
5. Expose findings through the API with stable identifiers.

## Observability

Use structured logs with stable field names. Never log secrets, tokens, or raw credentials. Treat logs as event streams suitable for aggregation (Twelve-Factor).
