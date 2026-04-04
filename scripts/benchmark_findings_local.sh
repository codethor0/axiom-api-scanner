#!/usr/bin/env bash
# Fixed local finding-quality benchmark: same stack as e2e-local (httpbin + Postgres + rules/builtin).
# Proves tier expectations for safe V1 rules on testdata/e2e/httpbin-openapi.yaml (no third-party targets).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="$ROOT/deploy/e2e/docker-compose.yml"
export COMPOSE_FILE

HTTPBIN_URL="${HTTPBIN_URL:-http://127.0.0.1:18080}"
AXIOM_URL="${AXIOM_URL:-http://127.0.0.1:8080}"
DATABASE_URL="${DATABASE_URL:-postgres://axiom:axiom@127.0.0.1:54334/axiom_e2e?sslmode=disable}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}

need_cmd docker
need_cmd curl
need_cmd jq
need_cmd go

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon not reachable" >&2
  exit 1
fi

docker compose -f "$COMPOSE_FILE" up -d axiom-pg httpbin

for i in $(seq 1 60); do
  if docker compose -f "$COMPOSE_FILE" exec -T axiom-pg pg_isready -U axiom -d axiom_e2e >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "postgres not ready" >&2
    exit 1
  fi
  sleep 1
done

go build -o "$ROOT/bin/axiom-api-bench" ./cmd/api

export DATABASE_URL
export AXIOM_RULES_DIR="$ROOT/rules"
export AXIOM_MIGRATIONS_DIR="$ROOT/migrations"
export AXIOM_HTTP_ADDR="${AXIOM_HTTP_ADDR:-127.0.0.1:8080}"

(
  cd "$ROOT"
  exec ./bin/axiom-api-bench
) &
API_PID=$!
cleanup() {
  kill "$API_PID" 2>/dev/null || true
}
trap cleanup EXIT

for i in $(seq 1 60); do
  if curl -sf "$AXIOM_URL/v1/rules" >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "API did not become ready at $AXIOM_URL" >&2
    exit 1
  fi
  sleep 1
done

curl -sf "$HTTPBIN_URL/get" | jq -e .url >/dev/null

SCAN_ID="$(
  curl -sf -X POST "$AXIOM_URL/v1/scans" \
    -H 'Content-Type: application/json' \
    -d '{"target_label":"bench-httpbin","safety_mode":"safe","allow_full_execution":false,"base_url":"'"$HTTPBIN_URL"'"}' |
    jq -er .id
)"

curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/specs/openapi" \
  -H 'Content-Type: application/x-yaml' \
  --data-binary @"$ROOT/testdata/e2e/httpbin-openapi.yaml" | jq -e '.count >= 1' >/dev/null

curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/executions/baseline" | jq -e '.result.status == "succeeded"' >/dev/null
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/executions/mutations" | jq -e '.result.status == "succeeded"' >/dev/null

FINDINGS="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/findings")"
N="$(echo "$FINDINGS" | jq '.items | length')"
if [[ "$N" -lt 1 ]]; then
  echo "benchmark inconclusive: zero findings (check rules, httpbin, import)" >&2
  exit 1
fi

echo "==> benchmark: $N finding(s) on scan $SCAN_ID"

# IDOR example rule uses response_body_similarity min_score 0.85 (< 0.9 weak-signal threshold) -> all such rows must be tentative.
BAD_IDOR="$(echo "$FINDINGS" | jq '[.items[] | select(.rule_id == "axiom.idor.path_swap.v1" and .assessment_tier != "tentative")] | length')"
if [[ "$BAD_IDOR" -ne 0 ]]; then
  echo "benchmark failed: idor rule findings must be tentative (weak similarity threshold), got non-tentative count $BAD_IDOR" >&2
  echo "$FINDINGS" | jq . >&2
  exit 1
fi

# Mass-assignment example uses only strong matchers -> any such finding must be confirmed.
BAD_MASS="$(echo "$FINDINGS" | jq '[.items[] | select(.rule_id == "axiom.mass.privilege_merge.v1" and .assessment_tier != "confirmed")] | length')"
if [[ "$BAD_MASS" -ne 0 ]]; then
  echo "benchmark failed: mass-assignment rule findings must be confirmed (no weak matchers in rule), got bad count $BAD_MASS" >&2
  echo "$FINDINGS" | jq . >&2
  exit 1
fi

# If idor produced a row, summary should surface assessment notes (weak_matcher_signal) in the one-line summary.
if echo "$FINDINGS" | jq -e 'any(.items[]?; .rule_id == "axiom.idor.path_swap.v1")' >/dev/null; then
  IDOR_SUMMARIES="$(echo "$FINDINGS" | jq -r '.items[] | select(.rule_id == "axiom.idor.path_swap.v1") | .summary')"
  if ! echo "$IDOR_SUMMARIES" | grep -q 'assessment: weak_matcher_signal'; then
    echo "benchmark failed: expected idor finding summary to include assessment notes" >&2
    echo "$IDOR_SUMMARIES" >&2
    exit 1
  fi
fi

echo "OK: finding-quality benchmark passed (httpbin + builtin rules)."
