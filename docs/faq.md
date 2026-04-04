# Frequently asked questions (v0.1.0-rc.1)

Answers are scoped to the **current** safe V1 surface. For positioning vs broader tools, see [comparison.md](comparison.md).

## What is Axiom?

A **safe-by-default**, **OpenAPI 3.x**-centric API abuse scanner with a **control-plane HTTP API**, YAML rules, and stored **findings** with explicit severity and assessment fields. See [README.md](../README.md).

## What category is Axiom trying to win?

**Evidence-first, low-blast-radius** triage for **OpenAPI-first** teams: bounded mutations, clear read models—not “crawl and fuzz everything” DAST on day one. Details: [comparison.md](comparison.md).

## What does V1 actually check?

Four builtin-oriented **families** (see [benchmark-results.md](benchmark-results.md)):

| In plain language | Technical label |
| --- | --- |
| Swapping identifiers in path or query | IDOR path/query swap |
| Privilege-style fields merged into bodies | Mass assignment privilege injection |
| Paths that differ by normalization | Path normalization bypass |
| Rotating headers around rate-limit signals | Rate limit header rotation |

## What does Axiom **not** do yet?

- Replace full enterprise DAST or every API input format.
- Act as an unrestricted fuzzer or exploit framework.
- Guarantee coverage of every auth scheme or every OpenAPI edge case.
- Run heavy Docker proof **inside** default GitHub Actions (those are **local** recipes). See [testing.md](testing.md#proof-matrix-ci-vs-local-vs-environment).

## Where is the published release candidate?

- **Release page:** https://github.com/codethor0/axiom-api-scanner/releases/tag/v0.1.0-rc.1  
- **Tag:** `v0.1.0-rc.1`

## Is there an official Docker / GHCR image?

The repo includes a **`Dockerfile`** and **`make docker-build-api`** so you can build the API image locally or in **your** registry (for example GHCR or Docker Hub under **your** org). There is no **mandatory** public image maintained by the project for **`v0.1.0-rc.1`**; some teams prefer to build from the tagged source. See [README.md](../README.md#quickstart-docker) and [testing.md](testing.md#docker-api-image-packaging).

## What is the difference between CI proof and local proof?

| Layer | Runs in GitHub Actions? | What it shows |
| --- | --- | --- |
| **CI** | Yes | Migration layout, `bash -n` on proof scripts, `go vet`, `golangci-lint`, `go test ./...` with Postgres |
| **Local e2e** | No (`make e2e-local`) | Real Docker stack: API + Postgres + httpbin; curl/jq checks on scan lifecycle |
| **Local benchmark** | No (`make benchmark-findings-local`) | Same stack + rate stub; **tier** and **`bench_summary`** matrix for V1 families |

**One-shot local recipe:** `make release-candidate-proof` (runs e2e then benchmark sequentially). See [testing.md](testing.md).

## Why did my Docker proof fail with “address already in use”?

`e2e-local` and `benchmark-findings-local` both default to API on **8080**. Run them one after another, use `make release-candidate-proof`, or override `AXIOM_HTTP_ADDR` / `AXIOM_URL` per [testing.md](testing.md#proof-matrix-ci-vs-local-vs-environment).

## How do I report a false positive or false negative?

Open a **Bug report** issue with reproduction steps, spec or rule id, and whether you ran `make ci-unit` or the Docker targets. See [CONTRIBUTING.md](../CONTRIBUTING.md). False positives and false negatives are **first-class** feedback for this RC phase.

## Does Axiom support GraphQL, gRPC, or SOAP?

**OpenAPI 3.x** is the first-class ingestion path for V1. Other formats are **out of scope** unless explicitly added later; say what you need in a **Feature request** (auth/spec coverage gaps welcome).

## What about the worker binary?

The **worker** entrypoint is largely **scaffold**; orchestration for the documented V1 paths runs **in-process** as described in [architecture.md](architecture.md) and [CHANGELOG.md](../CHANGELOG.md).

## How do I report a security vulnerability in Axiom itself?

Follow [SECURITY.md](../SECURITY.md). Do **not** post undisclosed vulnerability details in public issues.
