# Shared checks for Docker-backed local scripts (benchmark, e2e-local).
# shellcheck shell=bash

require_repo_paths() {
  local root="$1"
  local compose_file="$2"
  if [[ ! -f "$compose_file" ]]; then
    echo "local stack: missing compose file: $compose_file" >&2
    echo "local stack: run from repository root; clone must include deploy/e2e/." >&2
    exit 1
  fi
  if [[ ! -d "$root/rules" ]]; then
    echo "local stack: missing $root/rules (AXIOM_RULES_DIR is set from this tree)." >&2
    exit 1
  fi
  if [[ ! -d "$root/migrations" ]]; then
    echo "local stack: missing $root/migrations" >&2
    exit 1
  fi
  if [[ ! -f "$root/testdata/e2e/httpbin-openapi.yaml" ]]; then
    echo "local stack: missing $root/testdata/e2e/httpbin-openapi.yaml (benchmark/e2e fixture)." >&2
    exit 1
  fi
}

require_docker_daemon() {
  if ! docker info >/dev/null 2>&1; then
    echo "local stack: docker daemon not reachable. Start Docker Desktop or dockerd; on Linux you may need permission to the docker socket." >&2
    exit 1
  fi
}
