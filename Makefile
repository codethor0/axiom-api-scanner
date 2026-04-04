.PHONY: build test fmt vet lint check-migrations workflow-lint ci ci-unit run-api migrate-up migrate-down test-integration e2e-local e2e-crapi e2e-crapi-auth benchmark-findings-local release-candidate-proof

# CLI migrate must match github.com/golang-migrate/migrate/v4 used by internal/dbmigrate.
MIGRATE ?= go run -tags postgres github.com/golang-migrate/migrate/v4/cmd/migrate@v4.17.1

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

# Local release-candidate proof: static checks + unit tests + Docker e2e + benchmark.
# Requires: Docker, curl, jq, Go. Postgres integration in go test is optional unless AXIOM_TEST_DATABASE_URL is set (see docs/testing.md).
release-candidate-proof: check-migrations vet lint
	@echo "release-candidate-proof: go test (set AXIOM_TEST_DATABASE_URL for postgres integration tests)"
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
