# Demo script / video outline

Use this for a **10–15 minute** walkthrough. Adjust depth for your audience (engineers vs security leadership). **Do not** demo against systems you are not authorized to test.

## Setup (show once)

- Repository: https://github.com/codethor0/axiom-api-scanner
- Release (optional intro slide): https://github.com/codethor0/axiom-api-scanner/releases/tag/v0.1.0-rc.1
- Clone, `cd` to repo root. Show `go.mod` / Go version expectation.

## Beat 1 — What it is (60–90 seconds)

- Open [comparison.md](comparison.md): **OpenAPI-first**, **bounded V1 families**, **evidence stored in findings**, not a general DAST replacement.
- List the four families (same wording as README): IDOR path/query swap, mass assignment privilege injection, path normalization bypass, rate limit header rotation.

## Beat 2 — Proof story (90 seconds)

- Open [testing.md](testing.md) **Proof matrix** table.
- State clearly: **GitHub Actions** = compile-time discipline + **`go test`** with Postgres + script syntax checks; it does **not** run Docker e2e or the benchmark.
- **Local** = `make e2e-local` (httpbin stack) and `make benchmark-findings-local` (adds rate stub + `bench_summary` matrix).
- Mention **port contention**: run e2e and benchmark **sequentially** or use **`make release-candidate-proof`** (runs both in order).

## Beat 3 — Live path A: no Docker (~3 minutes)

- Run: `make ci-unit` (or `make check-migrations && go vet ./... && golangci-lint run && go test ./... -count=1`).
- Expect: passes on a normal dev machine; note Postgres **integration** tests **skip** unless `AXIOM_TEST_DATABASE_URL` is set (optional one-liner).

## Beat 3b — Docker API image smoke (~2 minutes, optional)

- Run: `make docker-api-smoke` (builds image, ephemeral Postgres, **`GET /v1/rules`**).
- Success line: `OK: docker API smoke passed ...`
- Say: this checks **packaging**, not the full **e2e-local** or **benchmark** matrix.

## Beat 4 — Live path B: Docker e2e (~4 minutes, optional)

- Preconditions: Docker running, ports **54334**, **18080**, **8080** free (defaults).
- Run: `make e2e-local`.
- Success line to show: `OK: local e2e validation passed (httpbin path + orchestrator smoke).`
- If short on time: show a pre-recorded terminal capture instead.

## Beat 5 — Live path C: benchmark (optional, ~3 minutes)

- Run **after** e2e completes (or on a fresh machine with ports free): `make benchmark-findings-local`.
- Success line: `OK: finding-quality benchmark passed ...`
- Point at **`bench_summary`** lines and [benchmark-results.md](benchmark-results.md) reference table.

## Beat 6 — Operator journey (~2 minutes)

- Skim [README.md](../README.md) **Quickstart**: Postgres, `go build`, start API, `POST /v1/scans`, import OpenAPI, `POST .../run`.
- Point to [api.md](api.md) for read paths (`/v1/findings`, evidence).

## Closing (~30 seconds)

- **Not** claiming “best API scanner.” **Is** claiming a **reproducible RC** and a **clear** wedge for OpenAPI teams.
- Ask for issues: false positives, false negatives, setup friction, auth/spec gaps — see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Checklist before recording

- [ ] Authorized demo target only (or localhost fixtures only).
- [ ] Terminal font size readable; redacted any local paths if needed.
- [ ] If live Docker fails, have a recorded fallback clip.
