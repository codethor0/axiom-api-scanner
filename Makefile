.PHONY: build test fmt lint run-api

build:
	go build -o bin/axiom-api ./cmd/api
	go build -o bin/axiom-worker ./cmd/worker

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

lint:
	golangci-lint run

run-api: build
	AXIOM_RULES_DIR=./rules AXIOM_HTTP_ADDR=:8080 ./bin/axiom-api
