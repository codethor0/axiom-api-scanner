# Comparison and positioning (V1)

This document is **scoped** to what **Axiom** ships **today**: a **safe-by-default**, **OpenAPI 3.x**-centric scanner with a **control-plane HTTP API**, **YAML rules**, and a **bounded V1** mutation and finding pipeline. It does **not** claim “best API scanner in the world.” It states **which category** the project targets and what **evidence** backs that claim.

## Category we are trying to win

**Evidence-first, low-blast-radius API abuse triage** for teams that already have (or can import) **OpenAPI**, need **clear findings** (`severity`, `assessment_tier`, `rule_declared_confidence`, evidence payloads), and want **deterministic, safe** mutation families—not full generic DAST coverage on day one.

## V1 mutation / finding families (current)

Aligned with **`rule_family_coverage`** vocabulary in the API:

| Family | Intent |
| --- | --- |
| **IDOR path or query swap** | Path/query identifier manipulation (broken object level authorization class). |
| **Mass assignment / privilege injection** | Unsafe mass-assignment style probes where rules allow. |
| **Path normalization bypass** | Normalization-sensitive path variants. |
| **Rate limit header rotation** | Controlled header rotation around rate-limit signals (bounded; target-dependent). |

Builtin example rules live under **`rules/builtin/`**; see [rule-authoring.md](rule-authoring.md).

## What broader tools typically add (honest gap)

General DAST and API-security products often emphasize:

- **More input surfaces:** SOAP/WSDL, GraphQL, Postman collections, traffic-based discovery, **broader** active scanning defaults.
- **Larger rule/attack catalogs** and **enterprise** workflows (ticketing, dashboards, blocking proxies).

Axiom **does not** match that breadth in V1. The **wedge** is narrower: **OpenAPI-first**, **explicit safety modes**, **stored executions + findings** with **stable read APIs** and **navigation hints** for operators.

## Proof expectations (factual)

| Proof | What it shows | Where |
| --- | --- | --- |
| **CI** | Migration layout; shell **syntax** of proof scripts (`bash -n` only); **`go vet`**; **lint**; **`go test ./...`** with Postgres in GitHub Actions | `.github/workflows/ci.yml`, [testing.md](testing.md#ci-vs-local) |
| **Contract / unit** | List envelopes, **`scan_navigation`**, run-status **`drilldown`**, list/detail parity (in-memory `httptest`) | `internal/api/*_test.go` |
| **Local e2e** | Docker Compose (Postgres + httpbin): import, baseline/mutations, run status, executions, findings, evidence, orchestrator smoke | `make e2e-local`, [testing.md](testing.md#local-docker-end-to-end-v1) |
| **Local benchmark** | Same stack + **nginx rate stub**; **tier** and harness **`bench_*`** matrix for builtin families | `make benchmark-findings-local`, [testing.md](testing.md#finding-quality-benchmark-local-httpbin-and-nginx-rate-stub) |

**CI does not** run **`make e2e-local`** or **`make benchmark-findings-local`**. Evaluators should run **`make release-candidate-proof`** (or those targets individually) on a clean clone with Docker. See the **Proof matrix** in [testing.md](testing.md#proof-matrix-ci-vs-local-vs-environment).

## How to use this doc

- **Selecting a tool:** If you need **GraphQL/SOAP/Postman** discovery or **widest** attack surface, compare vendors and OSS leaders directly; Axiom may be **complementary**, not a drop-in replacement.
- **Evaluating Axiom:** Run the **proof commands** above; inspect **read models** in [api.md](api.md) and **architecture** in [architecture.md](architecture.md).

## Change policy

When families or inputs expand, update this file in the **same change** so positioning stays honest.
