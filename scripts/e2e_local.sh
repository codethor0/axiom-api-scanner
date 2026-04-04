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
EXEC_N="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/executions" | jq '.items | length')"
[[ "$EXEC_N" -ge 1 ]]

echo "==> E2E: findings list"
FINDINGS_JSON="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/findings")"
echo "$FINDINGS_JSON" | jq -e '(.items | type == "array") and (.meta | type == "object")' >/dev/null
# May be zero or more depending on rules + matcher outcomes; require we can read the model
FIRST_LEN="$(echo "$FINDINGS_JSON" | jq '.items | length')"

if [[ "$FIRST_LEN" -ge 1 ]]; then
  FID="$(echo "$FINDINGS_JSON" | jq -er '.items[0].id')"
  echo "==> E2E: finding detail + evidence ($FID)"
  curl -sf "$AXIOM_URL/v1/findings/$FID" | jq -e .id >/dev/null
  curl -sf "$AXIOM_URL/v1/findings/$FID/evidence" | jq -e .finding_id >/dev/null
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
