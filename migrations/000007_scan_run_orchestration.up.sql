ALTER TABLE scans
    ADD COLUMN run_phase TEXT NOT NULL DEFAULT 'planned',
    ADD COLUMN run_error TEXT NOT NULL DEFAULT '';

ALTER TABLE execution_records
    ADD COLUMN candidate_key TEXT;

CREATE INDEX execution_records_scan_mutation_candidate_idx
    ON execution_records (scan_id, scan_endpoint_id, rule_id, candidate_key)
    WHERE phase = 'mutated'
      AND candidate_key IS NOT NULL;

-- One finding per evidence tuple (mutation resume must not duplicate).
CREATE UNIQUE INDEX findings_evidence_dedup_idx ON findings (
    scan_id,
    rule_id,
    scan_endpoint_id,
    baseline_execution_id,
    mutated_execution_id
);
