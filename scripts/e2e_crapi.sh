#!/usr/bin/env bash
# End-to-end V1 validation against local OWASP crAPI (intentionally vulnerable API).
# Prerequisite: Docker. Clones crAPI into .cache/crapi on first run (not committed).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CRAPI_ROOT="${CRAPI_ROOT:-$ROOT/.cache/crapi}"
CRAPI_COMPOSE_DIR="$CRAPI_ROOT/deploy/docker"
COMPOSE_AXIOM="$ROOT/deploy/e2e/docker-compose.yml"

AXIOM_URL="${AXIOM_URL:-http://127.0.0.1:8080}"
CRAPI_BASE_URL="${CRAPI_BASE_URL:-http://127.0.0.1:8888}"
DATABASE_URL="${DATABASE_URL:-postgres://axiom:axiom@127.0.0.1:54334/axiom_e2e?sslmode=disable}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}

need_cmd docker
need_cmd curl
need_cmd jq
need_cmd go
need_cmd git

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon not reachable" >&2
  exit 1
fi

if [[ ! -f "$CRAPI_ROOT/openapi-spec/crapi-openapi-spec.json" ]]; then
  echo "==> clone OWASP crAPI (shallow, develop) into $CRAPI_ROOT"
  mkdir -p "$(dirname "$CRAPI_ROOT")"
  rm -rf "$CRAPI_ROOT"
  git clone --depth 1 --branch develop https://github.com/OWASP/crAPI.git "$CRAPI_ROOT"
fi

SPEC_FILE="$CRAPI_ROOT/openapi-spec/crapi-openapi-spec.json"

echo "==> crAPI: docker compose up (upstream stack; may take minutes on first run)"
( cd "$CRAPI_COMPOSE_DIR" && docker compose -f docker-compose.yml --compatibility up -d )

echo "==> wait for crAPI web ($CRAPI_BASE_URL/health)"
for i in $(seq 1 120); do
  if curl -sf "$CRAPI_BASE_URL/health" >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" -eq 120 ]]; then
    echo "crAPI web not ready; check docker logs for crapi-web" >&2
    exit 1
  fi
  sleep 2
done

echo "==> Axiom: postgres (e2e compose)"
docker compose -f "$COMPOSE_AXIOM" up -d axiom-pg

for i in $(seq 1 60); do
  if docker compose -f "$COMPOSE_AXIOM" exec -T axiom-pg pg_isready -U axiom -d axiom_e2e >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "axiom postgres not ready" >&2
    exit 1
  fi
  sleep 1
done

echo "==> build and start Axiom API"
go build -o "$ROOT/bin/axiom-api-e2e" ./cmd/api
export DATABASE_URL AXIOM_RULES_DIR="$ROOT/rules" AXIOM_MIGRATIONS_DIR="$ROOT/migrations"
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

for i in $(seq 1 60); do
  if curl -sf "$AXIOM_URL/v1/rules" >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "Axiom API not ready at $AXIOM_URL" >&2
    exit 1
  fi
  sleep 1
done

echo "==> crAPI E2E: scan + import official spec file (version-matched to clone)"
SCAN_ID="$(
  curl -sf -X POST "$AXIOM_URL/v1/scans" \
    -H 'Content-Type: application/json' \
    -d '{"target_label":"e2e-crapi","safety_mode":"safe","allow_full_execution":false,"base_url":"'"$CRAPI_BASE_URL"'"}' |
    jq -er .id
)"

curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/specs/openapi" \
  -H 'Content-Type: application/json' \
  --data-binary @"$SPEC_FILE" | jq -e '.count >= 1' >/dev/null

echo "==> baseline"
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/executions/baseline" | jq -e '.result.status == "succeeded"' >/dev/null

echo "==> mutations"
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_ID/executions/mutations" | jq -e '.result.status == "succeeded"' >/dev/null

N_FIND="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/findings" | jq 'length')"
[[ "$N_FIND" -ge 1 ]]

FID="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_ID/findings" | jq -er '.[0].id')"
curl -sf "$AXIOM_URL/v1/findings/$FID" | jq -e .id >/dev/null
curl -sf "$AXIOM_URL/v1/findings/$FID/evidence" | jq -e .finding_id >/dev/null

echo "==> orchestrator start then resume (idempotent)"
OScan="$(
  curl -sf -X POST "$AXIOM_URL/v1/scans" \
    -H 'Content-Type: application/json' \
    -d '{"target_label":"e2e-crapi-orch","safety_mode":"safe","allow_full_execution":false,"base_url":"'"$CRAPI_BASE_URL"'"}' |
    jq -er .id
)"
curl -sf -X POST "$AXIOM_URL/v1/scans/$OScan/specs/openapi" \
  -H 'Content-Type: application/json' \
  --data-binary @"$SPEC_FILE" >/dev/null

curl -sf -X POST "$AXIOM_URL/v1/scans/$OScan/run" \
  -H 'Content-Type: application/json' \
  -d '{"action":"start"}' | jq -e '.phase == "findings_complete"' >/dev/null

curl -sf -X POST "$AXIOM_URL/v1/scans/$OScan/run" \
  -H 'Content-Type: application/json' \
  -d '{"action":"resume"}' | jq -e '.phase == "findings_complete"' >/dev/null

echo "OK: crAPI-backed e2e passed (findings=$N_FIND). Primary scan id: $SCAN_ID"

if [[ "${RUN_AUTHENTICATED_LEG:-0}" != "1" ]]; then
  exit 0
fi

echo "==> authenticated leg: signup + login (crAPI identity API only, local target)"
EMAIL="axiom-e2e-$(date +%s)@example.com"
SIGNUP_PAYLOAD="$(jq -n --arg e "$EMAIL" '{email:$e,name:"Axiom E2E",number:"5550001999",password:"Test!123ab"}')"
curl -sf -X POST "$CRAPI_BASE_URL/identity/api/auth/signup" \
  -H 'Content-Type: application/json' \
  -d "$SIGNUP_PAYLOAD" >/dev/null

LOGIN_PAYLOAD="$(jq -n --arg e "$EMAIL" '{email:$e,password:"Test!123ab"}')"
TOK_JSON="$(curl -sf -X POST "$CRAPI_BASE_URL/identity/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$LOGIN_PAYLOAD")"
TOKEN="$(echo "$TOK_JSON" | jq -er .token)"

SCAN_AUTH="$(jq -n \
  --arg bu "$CRAPI_BASE_URL" \
  --arg tok "$TOKEN" \
  '{target_label:"e2e-crapi-auth",safety_mode:"safe",allow_full_execution:false,base_url:$bu,auth_headers:{Authorization:("Bearer " + $tok)}}' |
  curl -sf -X POST "$AXIOM_URL/v1/scans" -H 'Content-Type: application/json' -d @- | jq -er .id)"

curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_AUTH/specs/openapi" \
  -H 'Content-Type: application/json' \
  --data-binary @"$SPEC_FILE" | jq -e '.count >= 1' >/dev/null

echo "==> run/status coverage hints (auth configured)"
H="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_AUTH/run/status" | jq -r '.coverage.hints | join(" | ")')"
echo "    hints: $H"
if ! echo "$H" | grep -q "auth_headers are present"; then
  echo "expected coverage hint about auth_headers" >&2
  exit 1
fi

echo "==> authenticated baseline"
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_AUTH/executions/baseline" | jq -e '.result.status == "succeeded"' >/dev/null

echo "==> authenticated mutations"
curl -sf -X POST "$AXIOM_URL/v1/scans/$SCAN_AUTH/executions/mutations" | jq -e '.result.status == "succeeded"' >/dev/null

# Protected community create-post: baseline JSON POST with {} should reach the API with Bearer token (response may be 200 or 4xx depending on validation; not 401 if auth is accepted).
OK_POST="$(
  curl -sf "$AXIOM_URL/v1/scans/$SCAN_AUTH/executions?phase=baseline" |
  jq '[.[] | select(.phase=="baseline" and .request.method=="POST" and (.request.url | test("/community/api/v2/community/posts$")) and .response.status_code != 401)] | length'
)"
if [[ "${OK_POST:-0}" -lt 1 ]]; then
  echo "expected at least one baseline POST to /community/api/v2/community/posts without 401 when using JWT" >&2
  exit 1
fi

N_AUTH_FIND="$(curl -sf "$AXIOM_URL/v1/scans/$SCAN_AUTH/findings" | jq 'length')"
[[ "$N_AUTH_FIND" -ge 1 ]]

echo "OK: crAPI authenticated e2e passed (findings=$N_AUTH_FIND, scan_auth=$SCAN_AUTH, email=$EMAIL)"
