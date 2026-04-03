# HTTP API (V1 skeleton)

Base path: `/v1`

All responses are JSON unless noted. Request and response schemas will be formalized alongside OpenAPI or JSON Schema for the control plane itself.

## Scans

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/scans` | Create scan (stub). |
| `GET` | `/v1/scans/{scanID}` | Fetch scan (stub). |
| `POST` | `/v1/scans/{scanID}/start` | Start scan (stub transition). |
| `POST` | `/v1/scans/{scanID}/pause` | Pause scan (stub transition). |
| `POST` | `/v1/scans/{scanID}/cancel` | Cancel scan (stub transition). |

## Findings

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/v1/scans/{scanID}/findings` | List findings (stub empty list). |
| `GET` | `/v1/findings/{findingID}` | Fetch finding (stub). |
| `GET` | `/v1/findings/{findingID}/evidence` | Fetch evidence artifact (stub). |

## Rules

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/v1/rules` | List validated rules from `AXIOM_RULES_DIR`. |

## OpenAPI

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/specs/openapi/validate` | Body: raw OpenAPI YAML or JSON. Validates and returns `{ "status": "valid" }`. |
| `POST` | `/v1/specs/openapi/import` | Body: raw OpenAPI YAML or JSON. Returns extracted endpoints and count. |

## Limits

OpenAPI upload bodies are capped at 10 MiB in the skeleton handlers. Production should enforce authenticated upload, virus scanning if required by policy, and configurable limits.

## Errors

Errors return JSON `{ "error": "message" }` with an appropriate HTTP status.
