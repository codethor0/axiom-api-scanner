.PHONY: build test fmt lint run-api migrate-up migrate-down test-integration e2e-local e2e-crapi

# CLI migrate must match github.com/golang-migrate/migrate/v4 used by internal/dbmigrate.
MIGRATE ?= go run -tags postgres github.com/golang-migrate/migrate/v4/cmd/migrate@v4.17.1

build:
	go build -o bin/axiom-api ./cmd/api
	go build -o bin/axiom-worker ./cmd/worker

test:
	go test ./...

# PostgreSQL integration test (optional): export AXIOM_TEST_DATABASE_URL first.
test-integration:
	AXIOM_TEST_DATABASE_URL="$(AXIOM_TEST_DATABASE_URL)" go test ./internal/storage/postgres/ -run Integration -count=1

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
