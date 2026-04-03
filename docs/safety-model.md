# Safety model

## Principles

- **Safe by default.** Passive observation or low-risk mutations are the baseline. Anything that can meaningfully harm data integrity, availability, or accounts requires explicit opt-in.
- **Scope binding.** Only targets approved in configuration may be contacted. Out-of-scope hosts must be rejected before any network I/O.
- **Auditability.** Every request emitted by the scanner must be logged in structured form with correlation identifiers. Evidence bundles capture raw traffic needed to reproduce a finding.

## Safety modes

| Mode | Intent |
| --- | --- |
| `passive` | No payload mutation that changes server-side state beyond what a normal read-only client would do (for example cached GETs). |
| `safe` | bounded mutations that respect destructive=false and rate policies. |
| `full` | may include destructive or high-impact checks; **disabled by default** in configuration and per scan. |

## Destructive classification

Rules with `safety.destructive: true` must not execute unless:

1. The deployment enables destructive execution explicitly, and
2. The scan is created with a matching safety contract, and
3. Scope and rate limits still apply.

## Alignment

Control design language with OWASP API Security Top 10, ASVS, and relevant OWASP Cheat Sheets. Axiom encodes policy in rules and server configuration rather than ad-hoc prompts.

## Operational guidance

- Start with `passive` or `safe` for new targets.
- Promote to `full` only after legal authorization, capacity review, and rollback plans are documented.
- Separate production targets from lab fixtures in configuration; never point a production database URL at a `full` scan without a formal break-glass process.
