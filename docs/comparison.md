# Comparison and positioning (V1)

This document is **scoped** to what **Axiom** ships **today**: a **safe-by-default**, **OpenAPI 3.x**-centric scanner with a **control-plane HTTP API**, **YAML rules**, and a **bounded V1** mutation and finding pipeline. It does **not** claim “best API scanner in the world.” It states **which category** the project targets and what **evidence** backs that claim.

## Category we are trying to win

**Evidence-first, low-blast-radius API abuse triage** for **OpenAPI-first** engineering teams: clear findings (`severity`, `assessment_tier`, `rule_declared_confidence`, evidence payloads), **deterministic** bounded mutations, and **operator-friendly** read paths—not a generic “scan everything” DAST on day one.

## V1 mutation / finding families (current)

Aligned with **`rule_family_coverage`** in the API (see [benchmark-results.md](benchmark-results.md) for expected benchmark outcomes):

| Family (positioning) | Intent |
| --- | --- |
| **IDOR path/query swap** | Path/query identifier manipulation (BOLA / IDOR class). |
| **Mass assignment privilege injection** | Unsafe mass-assignment style probes where rules allow. |
| **Path normalization bypass** | Normalization-sensitive path variants. |
| **Rate limit header rotation** | Controlled header rotation around rate-limit signals (bounded; **target-dependent**). |

Builtin example rules live under **`rules/builtin/`**; see [rule-authoring.md](rule-authoring.md).

## Reference landscape (category level only)

Other tools **often** emphasize broader **API definition** imports, **larger** attack catalogs, or **enterprise** workflows. Examples frequently cited in the market (not exhaustive, not version-pinned here):

| Class | What they tend to optimize for (high level) |
| --- | --- |
| **OWASP ZAP** API automation | API definitions (e.g. OpenAPI) feeding **API-tuned** scanning; wider format and workflow coverage than Axiom V1. |
| **Burp Suite** API scanning | API imports (e.g. OpenAPI, WSDL, collections), professional **consolidated** workflow. |
| **StackHawk** | **Discovery** and spec-oriented developer workflows, CI integration. |
| **42Crunch** | **Contract** audit, runtime testing, and API protection product lines. |

Axiom **does not** claim parity with those scopes. It targets the **narrow wedge** above with **explicit safety modes**, **stored evidence**, and **stable HTTP read models**.

**Packaging:** the control-plane API ships as a **`Dockerfile`**, **`make docker-*`** targets, and **GHCR** publishes from [`.github/workflows/container-publish.yml`](https://github.com/codethor0/axiom-api-scanner/blob/main/.github/workflows/container-publish.yml) (`ghcr.io/codethor0/axiom-api-scanner`)—see [README.md](../README.md#quickstart-docker-from-ghcr).

## What Axiom does not do yet (honest gap)

- **Not** a full replacement for broad DAST or every API input/format.
- **Not** maximum attack surface by default; **safe V1** is intentional.
- **Not** a substitute for authorization to test targets or for org policy/legal review.

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

## Feedback and traction

- **RC launch copy:** [announcement.md](announcement.md) (includes the published release URL).
- **Common questions:** [faq.md](faq.md).
- **Issues:** [CONTRIBUTING.md](../CONTRIBUTING.md) — false positives, false negatives, setup friction, and auth/spec gaps are especially useful.
