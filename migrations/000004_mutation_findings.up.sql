ALTER TABLE scans
    ADD COLUMN mutation_run_status TEXT,
    ADD COLUMN mutation_run_error TEXT,
    ADD COLUMN mutation_candidates_total INT NOT NULL DEFAULT 0,
    ADD COLUMN mutation_candidates_done INT NOT NULL DEFAULT 0,
    ADD COLUMN findings_count INT NOT NULL DEFAULT 0;

ALTER TABLE findings
    ADD COLUMN scan_endpoint_id UUID REFERENCES scan_endpoints (id) ON DELETE SET NULL,
    ADD COLUMN baseline_execution_id UUID REFERENCES execution_records (id) ON DELETE SET NULL,
    ADD COLUMN mutated_execution_id UUID REFERENCES execution_records (id) ON DELETE SET NULL,
    ADD COLUMN finding_status TEXT NOT NULL DEFAULT 'confirmed';

CREATE INDEX findings_scan_endpoint_idx ON findings (scan_endpoint_id);

CREATE INDEX execution_records_scan_phase_created_idx ON execution_records (scan_id, phase, created_at DESC);

CREATE INDEX execution_records_endpoint_phase_idx ON execution_records (scan_endpoint_id, phase, created_at DESC);
