#!/usr/bin/env bash
# Fixed local finding-quality benchmark: same stack as e2e-local (httpbin + Postgres + rules/builtin).
# Covers all four supported V1 mutation families via testdata/e2e/httpbin-openapi.yaml + rule outcomes:
#   - IDOR + path normalization: similarity@0.85 -> tentative + assessment notes weak_body_similarity_matcher + similarity_min_score_0.85
#   - Mass assignment: strong matchers -> confirmed
#   - Rate-limit header rotation: mutated httpbin responses do not satisfy header-diff matcher -> expect zero findings
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
    -d '{"target_label":"bench-httpbin-v1-families","safety_mode":"safe","allow_full_execution":false,"base_url":"'"$HTTPBIN_URL"'"}' |
    jq -er .id
)"

curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/specs/openapi" \
  -H 'Content-Type: application/x-yaml' \
  --data-binary @"$ROOT/testdata/e2e/httpbin-openapi.yaml" | jq -e '.count >= 1' >/dev/null

BASELINE_OUT="$(curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/executions/baseline")"
echo "$BASELINE_OUT" | jq -e '.result.status == "succeeded"' >/dev/null
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/executions/mutations" | jq -e '.result.status == "succeeded"' >/dev/null

RUN_STATUS="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/run/status")"
echo "$RUN_STATUS" | jq -e '.run.progression_source == "adhoc"' >/dev/null
echo "$RUN_STATUS" | jq -e '.run.findings_recording_status == "complete"' >/dev/null

FINDINGS="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/findings")"
N="$(echo "$FINDINGS" | jq '.items | length')"
if [[ "$N" -lt 1 ]]; then
  echo "benchmark inconclusive: zero findings (check rules, httpbin, import)" >&2
  exit 1
fi

echo "==> benchmark: $N finding(s) on scan $SCAN_ID"
echo "$FINDINGS" | jq -r '.items[] | "    finding: \(.rule_id) tier=\(.assessment_tier)"'

RULE_IDOR="axiom.idor.path_swap.v1"
RULE_MASS="axiom.mass.privilege_merge.v1"
RULE_PATHNORM="axiom.pathnorm.variant.v1"
RULE_RATELIMIT="axiom.ratelimit.header_rotate.v1"

expect_count() {
  local rule="$1"
  local want="$2"
  local got
  got="$(echo "$FINDINGS" | jq "[.items[] | select(.rule_id == \"$rule\")] | length")"
  if [[ "$got" != "$want" ]]; then
    echo "benchmark failed: expected $want finding(s) for $rule, got $got" >&2
    echo "$FINDINGS" | jq . >&2
    exit 1
  fi
}

all_tier() {
  local rule="$1"
  local tier="$2"
  local bad
  bad="$(echo "$FINDINGS" | jq "[.items[] | select(.rule_id == \"$rule\" and .assessment_tier != \"$tier\")] | length")"
  if [[ "$bad" != 0 ]]; then
    echo "benchmark failed: all $rule findings must be $tier" >&2
    echo "$FINDINGS" | jq . >&2
    exit 1
  fi
}

summaries_contain() {
  local rule="$1"
  local needle="$2"
  if ! echo "$FINDINGS" | jq -e "any(.items[]?; .rule_id == \"$rule\")" >/dev/null; then
    return 0
  fi
  local text
  text="$(echo "$FINDINGS" | jq -r ".items[] | select(.rule_id == \"$rule\") | .summary")"
  if ! echo "$text" | grep -q "$needle"; then
    echo "benchmark failed: expected $rule summary to contain $needle" >&2
    echo "$text" >&2
    exit 1
  fi
}

# Fixture + rules: expect exactly one row each for IDOR, mass, path norm; rate limit produces no finding on httpbin.
expect_count "$RULE_IDOR" 1
expect_count "$RULE_MASS" 1
expect_count "$RULE_PATHNORM" 1
expect_count "$RULE_RATELIMIT" 0

all_tier "$RULE_IDOR" "tentative"
all_tier "$RULE_MASS" "confirmed"
all_tier "$RULE_PATHNORM" "tentative"

summaries_contain "$RULE_IDOR" 'weak_body_similarity_matcher'
summaries_contain "$RULE_IDOR" 'similarity_min_score_0.85'
summaries_contain "$RULE_PATHNORM" 'weak_body_similarity_matcher'
summaries_contain "$RULE_PATHNORM" 'similarity_min_score_0.85'

# Evidence JSON: tentative rows carry the same assessment_notes as the list summary (read-path parity).
assert_tentative_evidence_notes() {
  local fid="$1"
  local detail
  detail="$(curl -sf "$AXIOM_URL/v1/findings/$fid")"
  echo "$detail" | jq -e '(.evidence_summary.assessment_notes | index("weak_body_similarity_matcher")) != null' >/dev/null
  echo "$detail" | jq -e '(.evidence_summary.assessment_notes | index("similarity_min_score_0.85")) != null' >/dev/null
  echo "$detail" | jq -e '.assessment_tier == "tentative"' >/dev/null
}

FID_IDOR="$(echo "$FINDINGS" | jq -er '.items[] | select(.rule_id == "'"$RULE_IDOR"'") | .id')"
FID_PATH="$(echo "$FINDINGS" | jq -er '.items[] | select(.rule_id == "'"$RULE_PATHNORM"'") | .id')"
assert_tentative_evidence_notes "$FID_IDOR"
assert_tentative_evidence_notes "$FID_PATH"

FID_MASS="$(echo "$FINDINGS" | jq -er '.items[] | select(.rule_id == "'"$RULE_MASS"'") | .id')"
MASS_DETAIL="$(curl -sf "$AXIOM_URL/v1/findings/$FID_MASS")"
echo "$MASS_DETAIL" | jq -e '.assessment_tier == "confirmed"' >/dev/null
echo "$MASS_DETAIL" | jq -e '(.evidence_summary.assessment_notes // []) | length == 0' >/dev/null

# Read-path: endpoint detail for an endpoint that has findings.
EP_ID="$(echo "$FINDINGS" | jq -er '.items[0].scan_endpoint_id')"
EP_DETAIL="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/endpoints/$EP_ID")"
echo "$EP_DETAIL" | jq -e '.drilldown.executions_list_path | startswith("/v1/")' >/dev/null
echo "$EP_DETAIL" | jq -e '.investigation != null' >/dev/null

# Execution detail: first finding's mutated execution (proves read path).
F0="$(echo "$FINDINGS" | jq '.items[0]')"
FID="$(echo "$F0" | jq -er .id)"
FGET="$(curl -sf "$AXIOM_URL/v1/findings/$FID")"
MEXEC="$(echo "$FGET" | jq -er '.mutated_execution_id // .evidence_summary.mutated_execution_id // empty')"
if [[ -z "$MEXEC" ]]; then
  echo "benchmark failed: could not resolve mutated_execution_id from finding detail" >&2
  echo "$FGET" | jq . >&2
  exit 1
fi
curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/executions/$MEXEC" | jq -e '.phase == "mutated"' >/dev/null

echo "OK: finding-quality benchmark passed (httpbin + builtin rules, four V1 families)."
