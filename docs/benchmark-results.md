# Benchmark results (Axiom V1, reproducible)

This document records **what the local benchmark proves** for the **current** safe V1 surface. It is **not** a head-to-head run against ZAP, Burp, StackHawk, or 42Crunch (those require separate methodology and permissions). For **category positioning**, see [comparison.md](comparison.md).

## This file does **not** prove (visibility first)

**Skip this section at your own risk when interpreting results.**

| Does **not** prove | Where to look instead |
| --- | --- |
| Anything about **your** production API, auth, or gateways | Run your own authorized tests; file [issues](https://github.com/codethor0/axiom-api-scanner/blob/main/CONTRIBUTING.md#issue-triage--pick-one-template) with repro |
| That **CI** ran this benchmark | [Three layers](#three-layers-of-proof-read-this-first) — Actions runs **`go test`**, not `make benchmark-findings-local` |
| That the **GHCR image** is healthy | [README — Clean machine](https://github.com/codethor0/axiom-api-scanner/blob/main/README.md#clean-machine-validation-ghcr) (`curl /v1/rules`) |
| Competitive ranking or **superiority** vs other scanners | This repo asserts **Axiom-only** regression outcomes; see [comparison.md](comparison.md#what-this-document-does-not-prove-read-first) |

The sections **What this benchmark proves** and **Does not prove** below repeat the same limits in detail.

## Three layers of proof (read this first)

| Layer | Where it runs | Role |
| --- | --- | --- |
| **CI** | GitHub Actions | `go test`, vet, lint, migrations, `bash -n` on scripts — **does not** execute this benchmark or Docker e2e |
| **Local e2e** | `make e2e-local` | Scan lifecycle on **httpbin** fixtures; proves API + compose wiring |
| **Local benchmark** | `make benchmark-findings-local` | This document: **tier** + **`bench_summary`** matrix across the **four V1 families** on controlled fixtures |

Full table: [testing.md](testing.md#proof-matrix-ci-vs-local-vs-environment). One command for e2e **then** benchmark: `make release-candidate-proof`.

## For outsiders: what the four families mean

These are **bounded** check types aligned with **`rule_family_coverage`** in the API (not an exhaustive OWASP checklist):

| Family | Plain-language intent |
| --- | --- |
| **IDOR path/query swap** | Mutations that swap or probe identifiers in **path or query** to detect **access control** issues in the style of BOLA/IDOR. |
| **Mass assignment privilege injection** | Request bodies that add **privilege-like** fields to probe **unsafe binding** / over-posting classes of bugs. |
| **Path normalization bypass** | Alternate **path spellings** (encoding, slashes, segments) that may **bypass** route or gateway normalization. |
| **Rate limit header rotation** | Controlled **header rotation** around rate-limit or throttling signals where rules and fixtures support it. |

## What this benchmark proves and does **not** prove

**Proves (on the **local** `make benchmark-findings-local` fixtures only):**

- The engine can run the **builtin example rules** against **httpbin** + a small **nginx rate stub** and persist **tiered** findings.
- For each **V1 family**, the harness produces a **`bench_summary`** outcome that matches the **reference matrix** below (row counts and **outcome class**). **Families are:** IDOR path/query swap, mass assignment privilege injection, path normalization bypass, rate limit header rotation — each is exercised according to the scan/fixture pairing in that table.
- **Operator meaning:** the benchmark shows the **plumbing** (planning, execution, persistence, read APIs) and **stable** outcomes on **controlled** targets. It is the project’s **honest** regression oracle for those four families — **not** a statement that every family finds a bug on every target.

**Does not prove:**

- Coverage of **your** production routes, auth flows, WAFs, API gateways, or business rules.
- **Detection quality** on arbitrary real APIs (only the **bundled** OpenAPI fixtures and rules).
- Parity with **any other** scanner or commercial tool — this document is **Axiom-only**; no comparative pass/fail rates are asserted.
- That **`rate_limit.header_rotate`** yields a finding on **httpbin** (it is often **`outcome_fixture_limited_no_row`** by design — the matrix documents why).
- That **CI** executed this flow: GitHub Actions does **not** run **`make benchmark-findings-local`** — see [testing.md](testing.md#ci-vs-local).
- **External trust** in the **GHCR image**: that is a **separate** surface (image pull + `GET /v1/rules`); see [README.md](../README.md#clean-machine-validation-ghcr).

## Category

**Evidence-first, low-blast-radius API abuse checks** for **OpenAPI-first** workflows: built-in coverage is expressed in terms of these **V1 families** (aligned with **`rule_family_coverage`** in the API):

| V1 family (operator wording) | `rule_family_coverage` key |
| --- | --- |
| IDOR path/query swap | `idor_path_or_query_swap` |
| Mass assignment privilege injection | `mass_assignment_privilege_injection` |
| Path normalization bypass | `path_normalization_bypass` |
| Rate limit header rotation | `rate_limit_header_rotation` |

## How to reproduce

From the **repository root**, with **Docker**, **curl**, **jq**, and **Go** available, default ports **54334**, **18080**, **18081**, **8080** free (or override per [testing.md](testing.md#local-docker-prerequisite-summary-e2e--benchmark)):

```text
make benchmark-findings-local
```

**Fixtures:** `testdata/e2e/httpbin-openapi.yaml` (scan A, httpbin), `testdata/e2e/bench-rate-limit-stub.yaml` (scan B, local nginx stub on **18081**). **Rules:** `rules/builtin/*.example.yaml`.

## Expected outcomes (Axiom-only)

The script ends with **`bench_summary_matrix`** lines (`bench_summary v=1 ...`). After a successful run you should see:

- Terminal line **`OK: finding-quality benchmark passed`**.
- **Nine** `bench_summary` lines: eight for scan A / scan B **cross** the four builtin rules, plus one line with **`phase=ci_github_actions`** explaining that matrix is **not** produced in GitHub Actions.

**Interpretation classes** (from script output):

| `outcome=` | Meaning on these fixtures |
| --- | --- |
| `outcome_confirmed_useful` | At least one row; **`confirmed`** tier on that finding. |
| `outcome_tentative_weak_signal` | At least one row; **`tentative`** (or similar) policy on that row. |
| `outcome_fixture_limited_no_row` | Zero rows because the target cannot satisfy matchers (httpbin + rate header rule). |
| `outcome_not_exercised_on_target` | Zero rows because that scan’s import/planner did not exercise that rule. |

### Reference matrix (expected on current builtin + fixtures)

| Phase | Target | Family | Expected finding rows | Expected outcome class |
| --- | --- | --- | --- | --- |
| scan_A | bench-httpbin-v1-families | IDOR path/query swap | 1 | `outcome_tentative_weak_signal` |
| scan_A | bench-httpbin-v1-families | Mass assignment privilege injection | 1 | `outcome_confirmed_useful` |
| scan_A | bench-httpbin-v1-families | Path normalization bypass | 2 | `outcome_tentative_weak_signal` |
| scan_A | bench-httpbin-v1-families | Rate limit header rotation | 0 | `outcome_fixture_limited_no_row` |
| scan_B | bench-rate-stub | IDOR path/query swap | 0 | `outcome_not_exercised_on_target` |
| scan_B | bench-rate-stub | Mass assignment privilege injection | 0 | `outcome_not_exercised_on_target` |
| scan_B | bench-rate-stub | Path normalization bypass | 1 | `outcome_tentative_weak_signal` |
| scan_B | bench-rate-stub | Rate limit header rotation | 1 | `outcome_confirmed_useful` |

If your run **disagrees** with this table, treat it as a regression or fixture drift—investigate before cutting a release.

## Timings

Wall time varies by machine and image pulls. The benchmark does **not** emit a stable timing artifact; record elapsed time manually if you need it for release notes.

## CI note

**GitHub Actions** does **not** execute this flow. **CI** runs `go test`, `go vet`, `golangci-lint`, migration checks, and `bash -n` on proof scripts. See [testing.md](testing.md#proof-matrix-ci-vs-local-vs-environment).
