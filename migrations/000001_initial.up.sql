CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status TEXT NOT NULL,
    target_label TEXT NOT NULL,
    safety_mode TEXT NOT NULL DEFAULT 'safe',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_uri TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE evidence_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    baseline_request TEXT NOT NULL,
    mutated_request TEXT NOT NULL,
    baseline_response_body TEXT NOT NULL,
    mutated_response_body TEXT NOT NULL,
    diff_summary TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX findings_scan_id_idx ON findings (scan_id);
CREATE INDEX evidence_artifacts_finding_id_idx ON evidence_artifacts (finding_id);
