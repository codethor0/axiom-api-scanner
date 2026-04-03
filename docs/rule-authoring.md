# Rule authoring

Rules are YAML documents validated at load time. Each rule must declare identification, risk, safety, targeting, mutations, matchers, and external references.

## Required fields

| Field | Description |
| --- | --- |
| `id` | Stable identifier (unique in a deployment). |
| `name` | Human title. |
| `category` | Taxonomy bucket (for example `broken_object_level_authorization`). |
| `severity` | Reported severity string (project conventions to be tightened). |
| `confidence` | Expected signal quality. |
| `safety.mode` | One of `passive`, `safe`, `full`. |
| `safety.destructive` | Boolean; destructive rules cannot run without explicit enablement. |
| `target.methods` | HTTP methods this rule may consider. |
| `target.where` | Selector describing parameter placement (for example `path_params.id`). |
| `prerequisites` | Declared requirements (session type, seed data). |
| `mutations` | Non-empty list of maps; each must include string `kind` and parameters. |
| `matchers` | Non-empty list of maps; each must include string `kind` and parameters. |
| `references` | Non-empty list of citations (OWASP links, standards). |
| `tags` | Free-form labels for filtering rule packs. |

## Example: passive readiness check

```yaml
id: axiom.example.ping
name: Health endpoint presence
category: configuration
severity: info
confidence: high
safety:
  mode: passive
  destructive: false
target:
  methods: [GET]
  where: path_exact /health
prerequisites: []
mutations:
  - kind: none
matchers:
  - kind: status_in
    allowed: [200, 204]
references:
  - https://owasp.org/www-project-api-security/
tags:
  - baseline
```

## Example: IDOR path swap (abbreviated)

This mirrors `rules/builtin/idor_path_swap.example.yaml`: swap an object identifier in the path while preserving session, then compare responses under configured matchers.

## Example: mass assignment probe (sketch)

```yaml
id: axiom.example.mass_assign.sketch
name: Mass assignment privilege field probe (sketch)
category: mass_assignment
severity: medium
confidence: low
safety:
  mode: safe
  destructive: false
target:
  methods: [PATCH, PUT, POST]
  where: json_body
prerequisites:
  - authenticated_session
mutations:
  - kind: merge_json_fields
    fields:
      is_admin: true
      role: owner
matchers:
  - kind: json_path_absent
    path: $.error
references:
  - OWASP API Security - Mass Assignment
tags:
  - mass-assignment
```

Schema enforcement will tighten allowed `kind` values for mutations and matchers as the engine gains capabilities.
