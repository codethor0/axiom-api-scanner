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

Yes for **this** repository: **`ghcr.io/codethor0/axiom-api-scanner`**. Images are built by [`.github/workflows/container-publish.yml`](https://github.com/codethor0/axiom-api-scanner/blob/main/.github/workflows/container-publish.yml) on **`push` to `main`**, on **git tags `v*`** (e.g. **`v0.1.0-rc.1`**), and **workflow_dispatch**. Tags include **`latest`** and **`sha-<short>`** from **`main`**, plus the **git tag** name for **`v*`** pushes.

If **`docker pull`** fails with **unauthorized** or **denied**, the package may still be **private**—sign in with **`docker login ghcr.io`** or ask a maintainer to make the package **public**. You can always build from the repo [`Dockerfile`](https://github.com/codethor0/axiom-api-scanner/blob/main/Dockerfile) via **`make docker-build-api`**. Pull/run flow: [README.md](../README.md#quickstart-docker-from-ghcr) and [testing.md](testing.md#ghcr-tag-scheme).

## What CPU architectures does the GHCR image support?

**Current policy:** the **container-publish** workflow builds a **multi-arch** image with **`linux/amd64`** and **`linux/arm64`** in one manifest list (QEMU in CI builds the non-native slice). **Apple Silicon** and **ARM64 Linux** hosts can **`docker pull`** the default tag and run **natively**.

**Older tags** created when the image was **amd64-only** still exist in the registry history; if **`docker pull`** errors with **no matching manifest for linux/arm64**, pin **`--platform linux/amd64`** or move to a **`latest`** (or other tag) produced after multi-arch publishing landed on **`main`**.

## What is the difference between CI proof and local proof?

| Layer | Runs in GitHub Actions? | What it shows |
| --- | --- | --- |
| **CI** | Yes | Migration layout, `bash -n` on proof scripts, `go vet`, `golangci-lint`, `go test ./...` with Postgres |
| **Local e2e** | No (`make e2e-local`) | Real Docker stack: API + Postgres + httpbin; curl/jq checks on scan lifecycle |
| **Local benchmark** | No (`make benchmark-findings-local`) | Same stack + rate stub; **tier** and **`bench_summary`** matrix for V1 families |
| **GHCR image** | No (you run it) | **Published** container starts against **your** Postgres; **`GET /v1/rules`** smoke — **no git clone** |

**One-shot local recipe:** `make release-candidate-proof` (runs e2e then benchmark sequentially). See [testing.md](testing.md).

**Three surfaces in one place:** [README.md](../README.md#proof-at-a-glance-three-separate-surfaces).

## What is the shortest “clean machine” path to trust the GHCR image?

Use Docker + **curl** only: pull **`ghcr.io/codethor0/axiom-api-scanner`** (tag of your choice), start **Postgres** on a user-defined network, run the API with **`DATABASE_URL`**, then **`curl -sf http://127.0.0.1:8080/v1/rules`**. Copy-paste steps: [README.md](../README.md#clean-machine-validation-ghcr). That validates **distribution and startup**, not benchmark/findings quality — for the latter, clone and run **`make benchmark-findings-local`** (see [benchmark-results.md](benchmark-results.md)).

## Where do I report a problem after that smoke test?

[CONTRIBUTING.md](../CONTRIBUTING.md#reporting-issues-after-external-validation) — use **Docker / GHCR** template for registry/pull issues; **Bug report** for false positives/negatives and auth/spec friction.

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
