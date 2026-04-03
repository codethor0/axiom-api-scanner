DROP INDEX IF EXISTS execution_records_endpoint_phase_idx;

DROP INDEX IF EXISTS execution_records_scan_phase_created_idx;

DROP INDEX IF EXISTS findings_scan_endpoint_idx;

ALTER TABLE findings
    DROP COLUMN IF EXISTS finding_status,
    DROP COLUMN IF EXISTS mutated_execution_id,
    DROP COLUMN IF EXISTS baseline_execution_id,
    DROP COLUMN IF EXISTS scan_endpoint_id;

ALTER TABLE scans
    DROP COLUMN IF EXISTS findings_count,
    DROP COLUMN IF EXISTS mutation_candidates_done,
    DROP COLUMN IF EXISTS mutation_candidates_total,
    DROP COLUMN IF EXISTS mutation_run_error,
    DROP COLUMN IF EXISTS mutation_run_status;
