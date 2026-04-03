# HTTP API (control plane)

Base path: `/v1`

All successful JSON responses use explicit structs. Errors use this envelope:

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "Human explanation"
  }
}
```

## Scans

### POST /v1/scans

Creates a persisted scan in `queued` status.

Request body:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `target_label` | string | yes | Non-empty, max 256 characters |
| `safety_mode` | string | yes | One of `passive`, `safe`, `full` |
| `allow_full_execution` | boolean | yes | Must be `true` when `safety_mode` is `full` |

`full` mode is opt-in: requests with `safety_mode: full` and `allow_full_execution: false` are rejected with code `full_mode_requires_opt_in`.

Response: `201` with the persisted scan (`id` is a UUID, timestamps come from PostgreSQL).

### GET /v1/scans/{scanID}

Returns a scan by UUID. `404` with code `not_found` when absent. Invalid UUID syntax returns `400` with `invalid_scan_id`.

### POST /v1/scans/{scanID}/control

Transitions scan state. Body: `{ "action": "start" | "pause" | "cancel" }`.

Valid transitions:

- `start`: `queued` or `paused` to `running`
- `pause`: `running` to `paused`
- `cancel`: `queued`, `running`, or `paused` to `canceled`

Invalid actions return `400` (`invalid_control_action`). Invalid transitions return `409` (`invalid_state_transition`). Unknown scan returns `404`.

### GET /v1/scans/{scanID}/findings

Lists findings for the scan. Returns `404` if the scan does not exist. Empty list is `[]` when there are no rows.

## Findings

### GET /v1/findings/{findingID}

Returns a finding row. `404` when missing.

### GET /v1/findings/{findingID}/evidence

Returns the first evidence artifact row for the finding. `404` when none exists.

## Rules

### GET /v1/rules

Returns validated YAML rules from `AXIOM_RULES_DIR`, including typed `mutations` and `matchers`.

## OpenAPI

### POST /v1/specs/openapi/validate

Body: raw OpenAPI 3.x YAML or JSON (max 10 MiB). Response: `{ "status": "valid" }` on success.

### POST /v1/specs/openapi/import

Body: same as validate. Response: `{ "endpoints": [...], "count": N }`.

## Service configuration errors

If scan persistence is not wired, scan and finding routes return `503` with `service_unavailable`. The production `cmd/api` binary always configures PostgreSQL repositories when `DATABASE_URL` is set.

## Operational limits

OpenAPI upload bodies are capped at 10 MiB. JSON bodies for scan and control requests are capped at 1 MiB.
