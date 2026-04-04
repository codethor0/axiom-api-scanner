# syntax=docker/dockerfile:1
# Minimal runtime image for the control-plane API only (no worker orchestration beyond what runs in-process).
# Supply DATABASE_URL at run time. Do not bake secrets into images.

FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/axiom-api ./cmd/api

FROM alpine:3.21
RUN apk add --no-cache ca-certificates \
  && addgroup -g 65532 axiom \
  && adduser -D -u 65532 -G axiom axiom

WORKDIR /app
COPY --from=build /out/axiom-api /app/axiom-api
COPY migrations /app/migrations
COPY rules /app/rules

USER axiom:axiom

ENV AXIOM_HTTP_ADDR=:8080 \
  AXIOM_RULES_DIR=/app/rules \
  AXIOM_MIGRATIONS_DIR=/app/migrations

EXPOSE 8080

ENTRYPOINT ["/app/axiom-api"]
