# Benchmark results (Axiom V1, reproducible)

This document records **what the local benchmark proves** for the **current** safe V1 surface. It is **not** a head-to-head run against ZAP, Burp, StackHawk, or 42Crunch (those require separate methodology and permissions). For **category positioning**, see [comparison.md](comparison.md).

## Three layers of proof (read this first)

| Layer | Where it runs | Role |
| --- | --- | --- |
| **CI** | GitHub Actions | `go test`, vet, lint, migrations, `bash -n` on scripts — **does not** execute this benchmark or Docker e2e |
| **Local e2e** | `make e2e-local` | Scan lifecycle on **httpbin** fixtures; proves API + compose wiring |
| **Local benchmark** | `make benchmark-findings-local` | This document: **tier** + **`bench_summary`** matrix across the **four V1 families** on controlled fixtures |

Full table: [testing.md](testing.md#proof-matrix-ci-vs-local-vs-environment). One command for e2e **then** benchmark: `make release-candidate-proof`.

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
