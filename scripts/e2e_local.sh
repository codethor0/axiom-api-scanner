#!/usr/bin/env bash
# Reproducible local V1 validation: Postgres + httpbin + Axiom API (host binary).
# Does not start OWASP crAPI (use scripts/e2e_crapi.sh or Makefile e2e-crapi).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="$ROOT/deploy/e2e/docker-compose.yml"
export COMPOSE_FILE

HTTPBIN_URL="${HTTPBIN_URL:-http://127.0.0.1:18080}"
AXIOM_URL="${AXIOM_URL:-http://127.0.0.1:8080}"
DATABASE_URL="${DATABASE_URL:-postgres://axiom:axiom@127.0.0.1:54334/axiom_e2e?sslmode=disable}"
CRAPI_OPENAPI_URL="${CRAPI_OPENAPI_URL:-}"
SKIP_CRAPI="${SKIP_CRAPI:-1}"

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

echo "==> compose: postgres + httpbin"
docker compose -f "$COMPOSE_FILE" up -d axiom-pg httpbin

echo "==> wait for Postgres"
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

echo "==> build Axiom API"
go build -o "$ROOT/bin/axiom-api-e2e" ./cmd/api

echo "==> start API (background)"
export DATABASE_URL
export AXIOM_RULES_DIR="$ROOT/rules"
export AXIOM_MIGRATIONS_DIR="$ROOT/migrations"
export AXIOM_HTTP_ADDR="${AXIOM_HTTP_ADDR:-127.0.0.1:8080}"
(
  cd "$ROOT"
  exec ./bin/axiom-api-e2e
) &
API_PID=$!
cleanup() {
  kill "$API_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> wait for API"
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

echo "==> httpbin health"
curl -sf "$HTTPBIN_URL/get" | jq -e .url >/dev/null

echo "==> E2E: create scan + target"
SCAN_ID="$(
  curl -sf -X POST "$AXIOM_URL/v1/scans" \
    -H 'Content-Type: application/json' \
    -d '{"target_label":"e2e-httpbin","safety_mode":"safe","allow_full_execution":false,"base_url":"'"$HTTPBIN_URL"'"}' |
    jq -er .id
)"
echo "    scan_id=$SCAN_ID"

echo "==> E2E: import OpenAPI"
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/specs/openapi" \
  -H 'Content-Type: application/x-yaml' \
  --data-binary @"$ROOT/testdata/e2e/httpbin-openapi.yaml" | jq -e '.count >= 1' >/dev/null

ENDPOINTS="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/endpoints")"
echo "    endpoints: $(echo "$ENDPOINTS" | jq '.items | length')"

echo "==> E2E: baseline"
BASELINE_JSON="$(curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/executions/baseline")"
echo "$BASELINE_JSON" | jq -e '.result.status == "succeeded"' >/dev/null

echo "==> E2E: mutations"
MUT_JSON="$(curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/executions/mutations")"
echo "$MUT_JSON" | jq -e '.result.status == "succeeded"' >/dev/null

echo "==> E2E: executions list"
EXEC_LIST="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/executions")"
EXEC_N="$(echo "$EXEC_LIST" | jq '.items | length')"
[[ "$EXEC_N" -ge 1 ]]

echo "==> E2E: execution detail (first row)"
EXEC_ID="$(echo "$EXEC_LIST" | jq -er '.items[0].id')"
EX_DETAIL="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/executions/$EXEC_ID")"
echo "$EX_DETAIL" | jq -e '
  (.phase == .execution_kind) and
  (.request.method != null) and
  (.request_summary.method == .request.method) and
  (.response_summary.status_code >= 100)
' >/dev/null

echo "==> E2E: run status (ad-hoc baseline/mutation scan)"
RUN_STATUS_JSON="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/run/status")"
echo "$RUN_STATUS_JSON" | jq -e '
  (.run.phase != null) and
  (.run.baseline_run_status != null) and
  (.drilldown.scan_id == "'"$SCAN_ID"'") and
  (.drilldown.findings_list_path | startswith("/v1/scans/")) and
  (.drilldown.executions_list_path | startswith("/v1/scans/")) and
  (.diagnostics.consistency_detail | type == "array") and
  (.diagnostics.blocked_detail | type == "array")
' >/dev/null
# Ad-hoc POST .../executions/baseline|mutations does not advance run_phase; phase stays "planned" while baseline/mutation counters reflect work.
echo "$RUN_STATUS_JSON" | jq -e '.run.phase == "planned"' >/dev/null
echo "$RUN_STATUS_JSON" | jq -e '.run.progression_source == "adhoc"' >/dev/null
echo "$RUN_STATUS_JSON" | jq -e '.run.findings_recording_status == "complete"' >/dev/null
echo "$RUN_STATUS_JSON" | jq -e '.run.baseline_run_status == "succeeded"' >/dev/null
echo "$RUN_STATUS_JSON" | jq -e '.run.mutation_run_status == "succeeded"' >/dev/null

echo "==> E2E: endpoint inventory detail + drilldown"
EP_ID="$(echo "$ENDPOINTS" | jq -er '.items[0].id')"
EP_DETAIL="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/endpoints/$EP_ID")"
echo "$EP_DETAIL" | jq -e '
  (.id == "'"$EP_ID"'") and
  (.investigation | type == "object") and
  (.drilldown.scan_endpoint_id == "'"$EP_ID"'") and
  (.drilldown.findings_list_query | contains("scan_endpoint_id="))
' >/dev/null

echo "==> E2E: findings list"
FINDINGS_JSON="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/findings")"
echo "$FINDINGS_JSON" | jq -e '(.items | type == "array") and (.meta | type == "object")' >/dev/null
# May be zero or more depending on rules + matcher outcomes; require we can read the model
FIRST_LEN="$(echo "$FINDINGS_JSON" | jq '.items | length')"

if [[ "$FIRST_LEN" -ge 1 ]]; then
  FID="$(echo "$FINDINGS_JSON" | jq -er '.items[0].id')"
  echo "==> E2E: finding detail + evidence ($FID)"
  FDETAIL="$(curl -sf "$AXIOM_URL/v1/findings/$FID")"
  echo "$FDETAIL" | jq -e '
    (.severity != null) and
    (.assessment_tier != null) and
    (.rule_declared_confidence != null) and
    (.evidence_inspection != null)
  ' >/dev/null
  curl -sf "$AXIOM_URL/v1/findings/$FID/evidence" | jq -e .finding_id >/dev/null
  SE_ID="$(echo "$FINDINGS_JSON" | jq -r '.items[0].scan_endpoint_id // empty')"
  if [[ -n "$SE_ID" ]]; then
    echo "==> E2E: findings list filtered by scan_endpoint_id"
    curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/findings?scan_endpoint_id=$SE_ID" | jq -e '(.items | length) >= 1' >/dev/null
  fi
fi

echo "==> E2E: orchestrated run (resume path smoke: second run)"
# Fresh scan for idempotent orchestration check
SCAN2="$(
  curl -sf -X POST "$AXIOM_URL/v1/scans" \
    -H 'Content-Type: application/json' \
    -d '{"target_label":"e2e-orchestrator","safety_mode":"safe","allow_full_execution":false,"base_url":"'"$HTTPBIN_URL"'"}' |
    jq -er .id
)"
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN2/specs/openapi" \
  -H 'Content-Type: application/x-yaml' \
  --data-binary @"$ROOT/testdata/e2e/httpbin-openapi.yaml" >/dev/null
RUN1="$(curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN2/run" \
  -H 'Content-Type: application/json' \
  -d '{"action":"start"}')"
echo "$RUN1" | jq -e '.run.phase == "findings_complete"' >/dev/null
PHASE1="$(echo "$RUN1" | jq -r .run.phase)"
RUN2="$(curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN2/run" \
  -H 'Content-Type: application/json' \
  -d '{"action":"resume"}')"
PHASE2="$(echo "$RUN2" | jq -r .run.phase)"
[[ "$PHASE1" == "$PHASE2" ]] || { echo "resume changed terminal phase unexpectedly" >&2; exit 1; }

echo "==> E2E: GET run/status after orchestrator + drilldown scan detail URL"
RS_ORCH="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN2/run/status")"
echo "$RS_ORCH" | jq -e '.run.phase == "findings_complete"' >/dev/null
echo "$RS_ORCH" | jq -e '.run.progression_source == "orchestrator"' >/dev/null
echo "$RS_ORCH" | jq -e '.run.findings_recording_status == "complete"' >/dev/null
SD_PATH="$(echo "$RS_ORCH" | jq -er '.drilldown.scan_detail_path')"
[[ "$SD_PATH" == "/v1/scans/$SCAN2" ]] || { echo "scan_detail_path mismatch: want /v1/scans/$SCAN2 got $SD_PATH" >&2; exit 1; }
curl -sf "$AXIOM_URL$SD_PATH" | jq -e '.id == "'"$SCAN2"'"' >/dev/null

if [[ "$SKIP_CRAPI" != "1" ]] && [[ -n "$CRAPI_OPENAPI_URL" ]]; then
  echo "==> Optional crAPI: import from $CRAPI_OPENAPI_URL"
  if curl -sfI "$CRAPI_OPENAPI_URL" | head -1 | grep -q '200'; then
    BS="http://127.0.0.1:8888"
    S3="$(
      curl -sf -X POST "$AXIOM_URL/v1/scans" \
        -H 'Content-Type: application/json' \
        -d '{"target_label":"e2e-crapi","safety_mode":"safe","allow_full_execution":false,"base_url":"'"$BS"'"}' |
        jq -er .id
    )"
    curl -sf "$CRAPI_OPENAPI_URL" | curl -sf -X POST "$AXIOM_URL/v1/scans/$S3/specs/openapi" \
      -H 'Content-Type: application/json' --data-binary @- | jq -e '.count >= 1' >/dev/null
    echo "    crAPI import ok (no automatic baseline/mutation here: scope review manually)"
  else
    echo "    crAPI OpenAPI URL not reachable, skip"
  fi
else
  echo "==> crAPI phase skipped (set SKIP_CRAPI=0 and CRAPI_OPENAPI_URL when crAPI is up)"
fi

echo "OK: local e2e validation passed (httpbin path + orchestrator smoke)."
