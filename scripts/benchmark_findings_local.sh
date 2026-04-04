#!/usr/bin/env bash
# Fixed local finding-quality benchmark: Postgres + httpbin + optional nginx rate-limit stub (compose).
# Scan A (httpbin): IDOR + path norm (two GET templates) + mass; rate-limit rule runs on httpbin but no finding.
# Scan B (127.0.0.1:18081 stub): one GET /rate-probe; builtin rate-limit rule -> confirmed finding (header differs).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# shellcheck source=local_stack_preflight.sh
source "$ROOT/scripts/local_stack_preflight.sh"
# shellcheck source=read_trust_assert.sh
source "$ROOT/scripts/read_trust_assert.sh"

COMPOSE_FILE="$ROOT/deploy/e2e/docker-compose.yml"
export COMPOSE_FILE

HTTPBIN_URL="${HTTPBIN_URL:-http://127.0.0.1:18080}"
RATE_STUB_URL="${RATE_STUB_URL:-http://127.0.0.1:18081}"
AXIOM_URL="${AXIOM_URL:-http://127.0.0.1:8080}"
DATABASE_URL="${DATABASE_URL:-postgres://axiom:axiom@127.0.0.1:54334/axiom_e2e?sslmode=disable}"

require_repo_paths "$ROOT" "$COMPOSE_FILE"
if [[ ! -f "$ROOT/testdata/e2e/bench-rate-limit-stub.yaml" ]]; then
  echo "benchmark: missing $ROOT/testdata/e2e/bench-rate-limit-stub.yaml (scan B OpenAPI fixture)." >&2
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "benchmark: missing required command on PATH: $1" >&2; exit 1; }
}

need_cmd docker
need_cmd curl
need_cmd jq
need_cmd go

require_docker_daemon

echo "==> benchmark preflight (local-only; not run in CI)"
echo "    compose: $COMPOSE_FILE"
echo "    httpbin: $HTTPBIN_URL  rate_stub: $RATE_STUB_URL  api: $AXIOM_URL"
echo "    DATABASE_URL host port should match axiom-pg publish (default 54334). Override env vars if ports conflict."

docker compose -f "$COMPOSE_FILE" up -d axiom-pg httpbin rate-limit-bench

for i in $(seq 1 60); do
  if docker compose -f "$COMPOSE_FILE" exec -T axiom-pg pg_isready -U axiom -d axiom_e2e >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "benchmark: postgres not ready after 60s (axiom-pg). Logs:" >&2
    docker compose -f "$COMPOSE_FILE" logs axiom-pg --tail 40 >&2 || true
    echo "benchmark: check nothing else bound compose port 54334; see deploy/e2e/docker-compose.yml" >&2
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
    echo "benchmark: API did not become ready at $AXIOM_URL (waited 60s)." >&2
    echo "benchmark: if port 8080 is busy, set AXIOM_HTTP_ADDR=127.0.0.1:<free> and the same host:port in AXIOM_URL." >&2
    exit 1
  fi
  sleep 1
done

if ! curl -sf "$HTTPBIN_URL/get" | jq -e .url >/dev/null; then
  echo "benchmark: httpbin not reachable at $HTTPBIN_URL (compose service httpbin, default host 18080)." >&2
  echo "benchmark: ensure docker compose brought httpbin up: docker compose -f $COMPOSE_FILE ps httpbin" >&2
  exit 1
fi
if ! curl -sf "$RATE_STUB_URL/rate-probe" >/dev/null; then
  echo "benchmark: rate-limit bench stub not reachable at $RATE_STUB_URL (compose rate-limit-bench, default 18081)." >&2
  exit 1
fi
# Baseline vs rotated identity: header must change (stub maps X-Forwarded-For 127.0.0.2 -> 7, default -> 10).
H_BASE="$(curl -sD - -o /dev/null "$RATE_STUB_URL/rate-probe" | tr -d '\r' | grep -i '^X-RateLimit-Remaining:' | awk '{print $2}')"
H_ROT="$(curl -sD - -o /dev/null -H 'X-Forwarded-For: 127.0.0.2' "$RATE_STUB_URL/rate-probe" | tr -d '\r' | grep -i '^X-RateLimit-Remaining:' | awk '{print $2}')"
if [[ -z "$H_BASE" || -z "$H_ROT" || "$H_BASE" == "$H_ROT" ]]; then
  echo "benchmark: rate-limit stub must return distinct X-RateLimit-Remaining (got base='$H_BASE' rotated='$H_ROT')." >&2
  echo "benchmark: check deploy/e2e/rate-limit-bench/nginx.conf and compose service rate-limit-bench logs." >&2
  docker compose -f "$COMPOSE_FILE" logs rate-limit-bench --tail 30 >&2 || true
  exit 1
fi

RULE_IDOR="axiom.idor.path_swap.v1"
RULE_MASS="axiom.mass.privilege_merge.v1"
RULE_PATHNORM="axiom.pathnorm.variant.v1"
RULE_RATELIMIT="axiom.ratelimit.header_rotate.v1"

BENCH_TARGET_HTTPBIN="bench-httpbin-v1-families"
BENCH_TARGET_STUB="bench-rate-stub"
# Kept in sync with internal/findings/benchmark_harness_test.go
BENCH_CODES_HTTPBIN_TENTATIVE="bench_target_httpbin_v1,bench_scanner_tentative_weak_similarity_policy,bench_fixture_layout_httpbin_openapi_operations"
BENCH_CODES_HTTPBIN_MASS_CONFIRMED="bench_target_httpbin_v1,bench_scanner_confirmed_useful_signal,bench_fixture_context_httpbin_post_mass_assignment"
BENCH_CODES_STUB_PATHNORM_TENTATIVE="bench_target_rate_stub,bench_scanner_tentative_weak_similarity_policy,bench_fixture_artifact_pathnorm_on_single_stub_route"
BENCH_CODES_STUB_RATE_CONFIRMED="bench_target_rate_stub,bench_scanner_confirmed_useful_signal,bench_fixture_context_rate_stub_header_differential"
BENCH_CODES_HTTPBIN_RATE_NO_ROW="bench_target_httpbin_v1,bench_no_finding_absent_row,bench_fixture_limit_httpbin_rate_header_matcher_unsatisfied"

bench_harness_codes_row() {
  local target="$1" fid="$2"
  local detail rule tier notes
  detail="$(curl -sf "$AXIOM_URL/v1/findings/$fid")"
  rule="$(echo "$detail" | jq -er .rule_id)"
  tier="$(echo "$detail" | jq -er .assessment_tier)"
  notes="$(echo "$detail" | jq -r '(.evidence_summary.assessment_notes // []) | join(",")')"
  ( cd "$ROOT" && go run ./scripts/benchharness -target "$target" -rule "$rule" -tier "$tier" -notes "$notes" )
}

assert_bench_harness_row() {
  local target="$1" fid="$2" want="$3"
  local got
  got="$(bench_harness_codes_row "$target" "$fid")"
  if [[ "$got" != "$want" ]]; then
    echo "benchmark failed: bench harness codes mismatch for finding $fid (want=$want got=$got)" >&2
    exit 1
  fi
}

assert_bench_harness_no_finding() {
  local target="$1" rule="$2" want="$3"
  local got
  got="$( ( cd "$ROOT" && go run ./scripts/benchharness -no-finding -target "$target" -rule "$rule" ) )"
  if [[ "$got" != "$want" ]]; then
    echo "benchmark failed: bench harness no-finding codes want=$want got=$got" >&2
    exit 1
  fi
}

SCAN_ID="$(
  curl -sf -X POST "$AXIOM_URL/v1/scans" \
    -H 'Content-Type: application/json' \
    -d '{"target_label":"'"$BENCH_TARGET_HTTPBIN"'","safety_mode":"safe","allow_full_execution":false,"base_url":"'"$HTTPBIN_URL"'"}' |
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
assert_scan_list_navigation_matches_scan "$FINDINGS" "$SCAN_ID"
assert_scan_list_navigation_matches_drilldown "$FINDINGS" "$RUN_STATUS"
BENCH_EXEC_LIST="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/executions")"
assert_scan_list_navigation_matches_scan "$BENCH_EXEC_LIST" "$SCAN_ID"
assert_scan_list_navigation_matches_drilldown "$BENCH_EXEC_LIST" "$RUN_STATUS"

echo "==> benchmark: $N finding(s) on scan $SCAN_ID"
echo "$FINDINGS" | jq -r '.items[] | "    finding: \(.rule_id) tier=\(.assessment_tier)"'

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

# Scan A: two GET path templates (/anything/{id}, /status/200) -> two path-normalization findings; httpbin cannot satisfy rate-limit header diff.
expect_count "$RULE_IDOR" 1
expect_count "$RULE_MASS" 1
expect_count "$RULE_PATHNORM" 2
expect_count "$RULE_RATELIMIT" 0

assert_bench_harness_no_finding "$BENCH_TARGET_HTTPBIN" "$RULE_RATELIMIT" "$BENCH_CODES_HTTPBIN_RATE_NO_ROW"
echo "    bench_harness scan=A no_row rule=${RULE_RATELIMIT} codes=${BENCH_CODES_HTTPBIN_RATE_NO_ROW}"

all_tier "$RULE_IDOR" "tentative"
all_tier "$RULE_MASS" "confirmed"
all_tier "$RULE_PATHNORM" "tentative"

summaries_contain "$RULE_IDOR" 'weak_body_similarity_matcher'
summaries_contain "$RULE_IDOR" 'similarity_min_score_0.85'
summaries_contain "$RULE_PATHNORM" 'weak_body_similarity_matcher'
summaries_contain "$RULE_PATHNORM" 'similarity_min_score_0.85'
summaries_contain "$RULE_IDOR" 'interpretation_body_similarity_min_below_0_9_keeps_tentative_tier'

# Evidence JSON: tentative rows carry the same assessment_notes as the list summary (read-path parity).
assert_tentative_evidence_notes() {
  local fid="$1"
  local detail
  detail="$(curl -sf "$AXIOM_URL/v1/findings/$fid")"
  echo "$detail" | jq -e '(.evidence_summary.assessment_notes | index("weak_body_similarity_matcher")) != null' >/dev/null
  echo "$detail" | jq -e '(.evidence_summary.assessment_notes | index("similarity_min_score_0.85")) != null' >/dev/null
  echo "$detail" | jq -e '.assessment_tier == "tentative"' >/dev/null
  echo "$detail" | jq -e '(.evidence_summary.interpretation_hints // [] | index("interpretation_body_similarity_min_below_0_9_keeps_tentative_tier")) != null' >/dev/null
}

assert_confirmed_evidence_no_interpretation_hints() {
  local fid="$1"
  local detail
  detail="$(curl -sf "$AXIOM_URL/v1/findings/$fid")"
  echo "$detail" | jq -e '.assessment_tier == "confirmed"' >/dev/null
  echo "$detail" | jq -e '(.evidence_summary.interpretation_hints // []) | length == 0' >/dev/null
}

FID_IDOR="$(echo "$FINDINGS" | jq -er '.items[] | select(.rule_id == "'"$RULE_IDOR"'") | .id')"
while read -r fid; do
  [[ -n "$fid" ]] || continue
  assert_tentative_evidence_notes "$fid"
done < <(echo "$FINDINGS" | jq -r '.items[] | select(.rule_id == "'"$RULE_PATHNORM"'") | .id')
assert_tentative_evidence_notes "$FID_IDOR"

while read -r fid; do
  [[ -n "$fid" ]] || continue
  assert_bench_harness_row "$BENCH_TARGET_HTTPBIN" "$fid" "$BENCH_CODES_HTTPBIN_TENTATIVE"
done < <(echo "$FINDINGS" | jq -r '.items[] | select(.rule_id == "'"$RULE_IDOR"'" or .rule_id == "'"$RULE_PATHNORM"'") | .id')

FID_MASS="$(echo "$FINDINGS" | jq -er '.items[] | select(.rule_id == "'"$RULE_MASS"'") | .id')"
assert_bench_harness_row "$BENCH_TARGET_HTTPBIN" "$FID_MASS" "$BENCH_CODES_HTTPBIN_MASS_CONFIRMED"
assert_confirmed_evidence_no_interpretation_hints "$FID_MASS"
MASS_DETAIL="$(curl -sf "$AXIOM_URL/v1/findings/$FID_MASS")"
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
assert_read_trust_legend_shape "$FGET"
assert_finding_evidence_comparison_when_paired "$FGET"
MEXEC="$(echo "$FGET" | jq -er '.mutated_execution_id // .evidence_summary.mutated_execution_id // empty')"
if [[ -z "$MEXEC" ]]; then
  echo "benchmark failed: could not resolve mutated_execution_id from finding detail" >&2
  echo "$FGET" | jq . >&2
  exit 1
fi
MEXEC_JSON="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/executions/$MEXEC")"
echo "$MEXEC_JSON" | jq -e '.phase == "mutated"' >/dev/null
assert_operator_guide_shape "$MEXEC_JSON"

# Scan B: nginx stub exposes differential X-RateLimit-Remaining for header-rotation mutations.
# The same GET endpoint is also eligible for path normalization (double-slash variant still matches nginx and passes weak similarity) -> tentative pathnorm + confirmed rate-limit (two findings).
SCAN_RL="$(
  curl -sf -X POST "$AXIOM_URL/v1/scans" \
    -H 'Content-Type: application/json' \
    -d '{"target_label":"'"$BENCH_TARGET_STUB"'","safety_mode":"safe","allow_full_execution":false,"base_url":"'"$RATE_STUB_URL"'"}' |
    jq -er .id
)"
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_RL/specs/openapi" \
  -H 'Content-Type: application/x-yaml' \
  --data-binary @"$ROOT/testdata/e2e/bench-rate-limit-stub.yaml" | jq -e '.count >= 1' >/dev/null
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_RL/executions/baseline" | jq -e '.result.status == "succeeded"' >/dev/null
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_RL/executions/mutations" | jq -e '.result.status == "succeeded"' >/dev/null

RUN_RL="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_RL/run/status")"
echo "$RUN_RL" | jq -e '.run.progression_source == "adhoc"' >/dev/null
echo "$RUN_RL" | jq -e '.run.findings_recording_status == "complete"' >/dev/null
echo "$RUN_RL" | jq -e '.rule_family_coverage.rate_limit_header_rotation.exercised == true' >/dev/null

FINDINGS_RL="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_RL/findings")"
assert_scan_list_navigation_matches_scan "$FINDINGS_RL" "$SCAN_RL"
assert_scan_list_navigation_matches_drilldown "$FINDINGS_RL" "$RUN_RL"
BENCH_EXEC_RL="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_RL/executions")"
assert_scan_list_navigation_matches_scan "$BENCH_EXEC_RL" "$SCAN_RL"
assert_scan_list_navigation_matches_drilldown "$BENCH_EXEC_RL" "$RUN_RL"
expect_count_rl() {
  local rule="$1"
  local want="$2"
  local got
  got="$(echo "$FINDINGS_RL" | jq "[.items[] | select(.rule_id == \"$rule\")] | length")"
  if [[ "$got" != "$want" ]]; then
    echo "benchmark failed (rate stub scan): expected $want finding(s) for $rule, got $got" >&2
    echo "$FINDINGS_RL" | jq . >&2
    exit 1
  fi
}

expect_count_rl "$RULE_IDOR" 0
expect_count_rl "$RULE_MASS" 0
expect_count_rl "$RULE_PATHNORM" 1
expect_count_rl "$RULE_RATELIMIT" 1
N_RL_TOTAL="$(echo "$FINDINGS_RL" | jq '.items | length')"
if [[ "$N_RL_TOTAL" != 2 ]]; then
  echo "benchmark failed (rate stub scan): expected exactly 2 findings, got $N_RL_TOTAL" >&2
  echo "$FINDINGS_RL" | jq . >&2
  exit 1
fi

bad_tier_rl="$(echo "$FINDINGS_RL" | jq "[.items[] | select(.rule_id == \"$RULE_RATELIMIT\" and .assessment_tier != \"confirmed\")] | length")"
if [[ "$bad_tier_rl" != 0 ]]; then
  echo "benchmark failed: rate-limit stub finding must be confirmed" >&2
  echo "$FINDINGS_RL" | jq . >&2
  exit 1
fi
bad_path_rl="$(echo "$FINDINGS_RL" | jq "[.items[] | select(.rule_id == \"$RULE_PATHNORM\" and .assessment_tier != \"tentative\")] | length")"
if [[ "$bad_path_rl" != 0 ]]; then
  echo "benchmark failed: stub path-normalization row must stay tentative (weak similarity)" >&2
  echo "$FINDINGS_RL" | jq . >&2
  exit 1
fi

FID_RL="$(echo "$FINDINGS_RL" | jq -er '.items[] | select(.rule_id == "'"$RULE_RATELIMIT"'") | .id')"
assert_bench_harness_row "$BENCH_TARGET_STUB" "$FID_RL" "$BENCH_CODES_STUB_RATE_CONFIRMED"
assert_confirmed_evidence_no_interpretation_hints "$FID_RL"
RL_DETAIL="$(curl -sf "$AXIOM_URL/v1/findings/$FID_RL")"
assert_read_trust_legend_shape "$RL_DETAIL"
assert_finding_evidence_comparison_when_paired "$RL_DETAIL"
echo "$RL_DETAIL" | jq -e '(.evidence_summary.assessment_notes // []) | length == 0' >/dev/null
FID_PATHSTUB="$(echo "$FINDINGS_RL" | jq -er '.items[] | select(.rule_id == "'"$RULE_PATHNORM"'") | .id')"
assert_bench_harness_row "$BENCH_TARGET_STUB" "$FID_PATHSTUB" "$BENCH_CODES_STUB_PATHNORM_TENTATIVE"
assert_tentative_evidence_notes "$FID_PATHSTUB"
EP_RL="$(echo "$FINDINGS_RL" | jq -er '.items[] | select(.rule_id == "'"$RULE_RATELIMIT"'") | .scan_endpoint_id')"
curl -sf "$AXIOM_URL/v1/scans/$SCAN_RL/endpoints/$EP_RL" | jq -e '.drilldown.findings_list_path | startswith("/v1/")' >/dev/null
RL_EXEC="$(echo "$RL_DETAIL" | jq -er '.mutated_execution_id')"
RL_EXEC_JSON="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_RL/executions/$RL_EXEC")"
echo "$RL_EXEC_JSON" | jq -e '.phase == "mutated"' >/dev/null
assert_operator_guide_shape "$RL_EXEC_JSON"

echo "    bench_harness scan=B pathnorm_fixture_artifact codes=${BENCH_CODES_STUB_PATHNORM_TENTATIVE}"

bench_rule_tier_first() {
  local items_json="$1"
  local rule="$2"
  echo "$items_json" | jq -r --arg r "$rule" '[.items[] | select(.rule_id == $r)][0].assessment_tier // empty'
}

bench_emit_matrix_row() {
  local phase="$1"
  local target="$2"
  local items_json="$3"
  local rule="$4"
  local cnt tier outcome family
  cnt="$(echo "$items_json" | jq --arg r "$rule" '[.items[] | select(.rule_id == $r)] | length')"
  tier="$(bench_rule_tier_first "$items_json" "$rule")"
  outcome="$( ( cd "$ROOT" && go run ./scripts/benchharness -outcome-class -target "$target" -rule "$rule" -tier "$tier" -count "$cnt" ) )"
  family="$( ( cd "$ROOT" && go run ./scripts/benchharness -rule-family -rule "$rule" ) )"
  echo "bench_summary v=1 phase=$phase target_label=$target rule_id=$rule family=$family finding_rows=$cnt outcome=$outcome"
}

emit_benchmark_summary_matrix() {
  echo "==> bench_summary_matrix (key=value lines; harness-only; see docs/testing.md)"
  local r
  for r in "$RULE_IDOR" "$RULE_MASS" "$RULE_PATHNORM" "$RULE_RATELIMIT"; do
    bench_emit_matrix_row scan_A "$BENCH_TARGET_HTTPBIN" "$FINDINGS" "$r"
  done
  for r in "$RULE_IDOR" "$RULE_MASS" "$RULE_PATHNORM" "$RULE_RATELIMIT"; do
    bench_emit_matrix_row scan_B "$BENCH_TARGET_STUB" "$FINDINGS_RL" "$r"
  done
  echo "bench_summary v=1 phase=ci_github_actions finding_rows=n/a outcome=outcome_not_in_matrix note=go_vet_golangci_go_test_postgres_only"
}

emit_benchmark_summary_matrix

echo "==> bench_outcome_legend (human-readable; same strings as outcome= in matrix)"
echo "    outcome_confirmed_useful: matchers passed; tier confirmed; empty interpretation_hints on row."
echo "    outcome_tentative_weak_signal: matchers passed; tier tentative (e.g. weak body similarity policy); interpretation_hints on row."
echo "    outcome_fixture_limited_no_row: expected zero rows because this target cannot satisfy matchers (httpbin + rate header rule)."
echo "    outcome_not_exercised_on_target: zero rows because this scan has no finding for that rule (planner/import); expected for idor/mass on stub-only import."

echo "OK: finding-quality benchmark passed (httpbin + rate stub, four V1 families with honest httpbin no-finding for rate limit)."
echo "==> benchmark exercised: scan_A id=$SCAN_ID (4 findings; 0 rows for $RULE_RATELIMIT on httpbin); scan_B id=$SCAN_RL (2 findings). bench_* + bench_summary above; API interpretation_hints are scanner-policy only."
echo "==> note: GitHub Actions runs go test/vet/lint (+ postgres tests); this Docker benchmark stays local."
