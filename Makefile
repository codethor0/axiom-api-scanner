.PHONY: build test fmt vet lint check-migrations workflow-lint ci ci-unit run-api migrate-up migrate-down test-integration e2e-local e2e-crapi e2e-crapi-auth benchmark-findings-local release-candidate-proof docker-build-api docker-run-api docker-pull-ghcr docker-run-ghcr docker-api-smoke docker-api-smoke-ghcr help

# OCI image for cmd/api only (local tag). Override when pushing to a registry, e.g. ghcr.io/codethor0/axiom-api-scanner:v0.1.0-rc.1
AXIOM_IMAGE ?= axiom-api-scanner:local

# Default pull target for published GHCR images (override tag, e.g. AXIOM_GHCR_IMAGE=ghcr.io/codethor0/axiom-api-scanner:v0.1.0-rc.1).
AXIOM_GHCR_IMAGE ?= ghcr.io/codethor0/axiom-api-scanner:latest

# CLI migrate must match github.com/golang-migrate/migrate/v4 used by internal/dbmigrate.
MIGRATE ?= go run -tags postgres github.com/golang-migrate/migrate/v4/cmd/migrate@v4.17.1

help:
	@echo "Axiom Makefile (run from repo root). See docs/testing.md and README.md."
	@echo "  External smoke (no clone): README.md ## Clean machine validation (GHCR)."
	@echo "  make help                      Show this list."
	@echo "  make ci-unit                   check-migrations + vet + lint + go test (postgres tests skip if AXIOM_TEST_DATABASE_URL unset)."
	@echo "  make ci                        Like CI workflow: requires AXIOM_TEST_DATABASE_URL for go test."
	@echo "  make e2e-local                 Docker e2e (httpbin); needs Docker, curl, jq."
	@echo "  make benchmark-findings-local  Docker benchmark + bench_summary; run after e2e or alone on free :8080."
	@echo "  make release-candidate-proof   check-migrations + vet + lint + go test + e2e-local + benchmark-findings-local (sequential)."
	@echo "  make docker-build-api          docker build API image ($(AXIOM_IMAGE))."
	@echo "  make docker-run-api            run $(AXIOM_IMAGE) (requires DATABASE_URL)."
	@echo "  make docker-pull-ghcr          docker pull $(AXIOM_GHCR_IMAGE)."
	@echo "  make docker-run-ghcr           same as docker-run-api with AXIOM_GHCR_IMAGE ($(AXIOM_GHCR_IMAGE))."
	@echo "  make docker-api-smoke          build $(AXIOM_IMAGE) + ephemeral Postgres + curl /v1/rules."
	@echo "  make docker-api-smoke-ghcr     docker pull $(AXIOM_GHCR_IMAGE) then smoke without rebuild (needs published image)."
	@echo "  make build / run-api           API binary; run-api needs DATABASE_URL."

docker-build-api:
	docker build -t $(AXIOM_IMAGE) -f Dockerfile .

# Run published-local API container. Example:
#   export DATABASE_URL=postgres://user:pass@host.docker.internal:5432/axiom?sslmode=disable
#   make docker-run-api
# Publish port 8080 on the host by default; override with AXIOM_HTTP_PUBLISH=3000:8080
AXIOM_HTTP_PUBLISH ?= 8080:8080
docker-run-api:
	@test -n "$(DATABASE_URL)" || (echo "docker-run-api: set DATABASE_URL (postgres://...)" >&2; exit 1)
	docker run --rm -p $(AXIOM_HTTP_PUBLISH) -e DATABASE_URL="$(DATABASE_URL)" $(AXIOM_IMAGE)

docker-pull-ghcr:
	docker pull $(AXIOM_GHCR_IMAGE)

docker-run-ghcr:
	@$(MAKE) docker-run-api AXIOM_IMAGE="$(AXIOM_GHCR_IMAGE)"

docker-api-smoke:
	chmod +x ./scripts/docker_api_smoke.sh
	AXIOM_DOCKER_SMOKE_IMAGE=$(AXIOM_IMAGE) ./scripts/docker_api_smoke.sh

docker-api-smoke-ghcr: docker-pull-ghcr
	chmod +x ./scripts/docker_api_smoke.sh
	AXIOM_DOCKER_SMOKE_SKIP_BUILD=1 AXIOM_DOCKER_SMOKE_IMAGE=$(AXIOM_GHCR_IMAGE) ./scripts/docker_api_smoke.sh

build:
	go build -o bin/axiom-api ./cmd/api
	go build -o bin/axiom-worker ./cmd/worker

test:
	go test ./...

# Same sequence as .github/workflows/ci.yml (requires Postgres — set AXIOM_TEST_DATABASE_URL).
ci: check-migrations vet lint test-ci

test-ci:
	@test -n "$(AXIOM_TEST_DATABASE_URL)" || (echo "ci: set AXIOM_TEST_DATABASE_URL to a dedicated Postgres URL (see docs/testing.md)." >&2; exit 1)
	AXIOM_TEST_MIGRATIONS_DIR="$(CURDIR)/migrations" AXIOM_TEST_DATABASE_URL="$(AXIOM_TEST_DATABASE_URL)" go test ./... -count=1

# Like CI but allows skipping DB-backed tests when AXIOM_TEST_DATABASE_URL is unset.
ci-unit: check-migrations vet lint
	go test ./... -count=1

check-migrations:
	./scripts/check_migrations.sh

# Optional: validate .github/workflows/*.yml (downloads actionlint via go run on first use; requires network).
workflow-lint:
	go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/*.yml

vet:
	go vet ./...

# PostgreSQL integration only (requires AXIOM_TEST_DATABASE_URL).
test-integration:
	@test -n "$(AXIOM_TEST_DATABASE_URL)" || (echo "AXIOM_TEST_DATABASE_URL is required" >&2; exit 1)
	AXIOM_TEST_MIGRATIONS_DIR="$(CURDIR)/migrations" AXIOM_TEST_DATABASE_URL="$(AXIOM_TEST_DATABASE_URL)" go test ./internal/storage/postgres/... -run '_integration$$' -count=1 -v

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

lint:
	golangci-lint run

# Requires DATABASE_URL (postgres://...). Run from repository root so ./migrations resolves.
migrate-up:
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required"; exit 1)
	$(MIGRATE) -path migrations -database "$(DATABASE_URL)" up

migrate-down:
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required"; exit 1)
	$(MIGRATE) -path migrations -database "$(DATABASE_URL)" down 1

run-api: build
	@test -n "$(DATABASE_URL)" || (echo "DATABASE_URL is required"; exit 1)
	AXIOM_RULES_DIR=./rules AXIOM_HTTP_ADDR=:8080 DATABASE_URL="$(DATABASE_URL)" ./bin/axiom-api

# Docker-backed local V1 flow (Postgres + httpbin). Requires docker, curl, jq, Go. See docs/testing.md.
e2e-local:
	@echo "e2e-local: needs Docker + repo checkout with deploy/e2e/, rules/, migrations/; see docs/testing.md (local Docker end-to-end)."
	./scripts/e2e_local.sh

# Finding-quality benchmark: httpbin + nginx rate stub + builtin rules (tier + bench_* harness). Not CI. See docs/testing.md.
benchmark-findings-local:
	@echo "benchmark-findings-local: needs Docker; default localhost ports 54334 18080 18081 8080 — override via env if busy (docs/testing.md)."
	chmod +x ./scripts/benchmark_findings_local.sh
	./scripts/benchmark_findings_local.sh

# Full local proof stack (maintainers / evaluators): migrations + vet + lint + go test, then Docker e2e, then benchmark (order matters for port 8080).
# Requires: Docker, curl, jq, Go. Postgres integration in go test is optional unless AXIOM_TEST_DATABASE_URL is set (see docs/testing.md).
release-candidate-proof: check-migrations vet lint
	@echo "release-candidate-proof: go test (set AXIOM_TEST_DATABASE_URL for postgres integration tests); then e2e-local; then benchmark-findings-local"
	AXIOM_TEST_MIGRATIONS_DIR="$(CURDIR)/migrations" go test ./... -count=1
	$(MAKE) e2e-local
	$(MAKE) benchmark-findings-local
	@echo "release-candidate-proof: OK (see also CHANGELOG.md and docs/comparison.md)."

# OWASP crAPI in Docker + Axiom (heavy images; first run clones upstream repo). See docs/testing.md.
e2e-crapi:
	chmod +x ./scripts/e2e_crapi.sh
	./scripts/e2e_crapi.sh

# Same as e2e-crapi plus signup/login JWT and authenticated scan leg (requires same Docker targets).
e2e-crapi-auth:
	chmod +x ./scripts/e2e_crapi.sh
	RUN_AUTHENTICATED_LEG=1 ./scripts/e2e_crapi.sh
