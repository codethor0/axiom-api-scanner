#!/usr/bin/env bash
# Build the API image and verify it starts against an ephemeral Postgres container.
# Requires: docker, curl. Destroys containers and network on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${AXIOM_DOCKER_SMOKE_IMAGE:-axiom-api-smoke:local}"
NET="${AXIOM_DOCKER_SMOKE_NET:-axiom-docker-smoke-$$}"
PG="${AXIOM_DOCKER_SMOKE_PG:-axiom-docker-smoke-pg-$$}"
API="${AXIOM_DOCKER_SMOKE_API:-axiom-docker-smoke-api-$$}"
HOST_PORT="${AXIOM_DOCKER_SMOKE_PORT:-18099}"

cleanup() {
  docker rm -f "$API" 2>/dev/null || true
  docker rm -f "$PG" 2>/dev/null || true
  docker network rm "$NET" 2>/dev/null || true
}
trap cleanup EXIT

docker build -t "$IMAGE" -f Dockerfile .
docker network create "$NET"
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_PASSWORD=axiom \
  -e POSTGRES_USER=axiom \
  -e POSTGRES_DB=axiom \
  postgres:16-alpine

echo "docker_api_smoke: waiting for Postgres"
for _ in $(seq 1 30); do
  if docker exec "$PG" pg_isready -U axiom -d axiom -q 2>/dev/null; then
    break
  fi
  sleep 1
done

docker run -d --name "$API" --network "$NET" -p "${HOST_PORT}:8080" \
  -e DATABASE_URL="postgres://axiom:axiom@${PG}:5432/axiom?sslmode=disable" \
  "$IMAGE"

echo "docker_api_smoke: waiting for API"
for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:${HOST_PORT}/v1/rules" >/dev/null 2>&1; then
    echo "OK: docker API smoke passed (GET /v1/rules on port ${HOST_PORT})."
    exit 0
  fi
  sleep 1
done

echo "docker_api_smoke: timeout waiting for /v1/rules" >&2
exit 1
