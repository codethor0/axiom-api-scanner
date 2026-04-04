DROP INDEX IF EXISTS findings_evidence_dedup_idx;

DROP INDEX IF EXISTS execution_records_scan_mutation_candidate_idx;

ALTER TABLE execution_records DROP COLUMN IF EXISTS candidate_key;

ALTER TABLE scans
    DROP COLUMN IF EXISTS run_phase,
    DROP COLUMN IF EXISTS run_error;
