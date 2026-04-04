.PHONY: build test fmt vet lint check-migrations ci ci-unit run-api migrate-up migrate-down test-integration e2e-local e2e-crapi e2e-crapi-auth

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

# Docker-backed local V1 flow (Postgres + httpbin). Requires docker, curl, jq. See docs/testing.md.
e2e-local:
	./scripts/e2e_local.sh

# OWASP crAPI in Docker + Axiom (heavy images; first run clones upstream repo). See docs/testing.md.
e2e-crapi:
	chmod +x ./scripts/e2e_crapi.sh
	./scripts/e2e_crapi.sh

# Same as e2e-crapi plus signup/login JWT and authenticated scan leg (requires same Docker targets).
e2e-crapi-auth:
	chmod +x ./scripts/e2e_crapi.sh
	RUN_AUTHENTICATED_LEG=1 ./scripts/e2e_crapi.sh
