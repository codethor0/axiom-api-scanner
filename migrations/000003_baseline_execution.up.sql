ALTER TABLE scans
    ADD COLUMN base_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN auth_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN baseline_run_status TEXT,
    ADD COLUMN baseline_run_error TEXT,
    ADD COLUMN baseline_endpoints_total INT NOT NULL DEFAULT 0,
    ADD COLUMN baseline_endpoints_done INT NOT NULL DEFAULT 0;

CREATE TABLE scan_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    path_template TEXT NOT NULL,
    operation_id TEXT NOT NULL DEFAULT '',
    security_scheme_hints JSONB NOT NULL DEFAULT '[]'::jsonb,
    request_content_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    response_content_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    request_body_json BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, method, path_template)
);

CREATE INDEX scan_endpoints_scan_id_idx ON scan_endpoints (scan_id);

CREATE TABLE execution_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    scan_endpoint_id UUID REFERENCES scan_endpoints (id) ON DELETE SET NULL,
    phase TEXT NOT NULL,
    rule_id TEXT,
    request_method TEXT NOT NULL,
    request_url TEXT NOT NULL,
    request_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    request_body TEXT NOT NULL DEFAULT '',
    response_status INT NOT NULL DEFAULT 0,
    response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_body TEXT NOT NULL DEFAULT '',
    response_content_type TEXT NOT NULL DEFAULT '',
    duration_ms INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX execution_records_scan_id_idx ON execution_records (scan_id);
