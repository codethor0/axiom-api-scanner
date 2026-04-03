DROP TABLE IF EXISTS execution_records;

DROP TABLE IF EXISTS scan_endpoints;

ALTER TABLE scans
    DROP COLUMN IF EXISTS base_url,
    DROP COLUMN IF EXISTS auth_headers,
    DROP COLUMN IF EXISTS baseline_run_status,
    DROP COLUMN IF EXISTS baseline_run_error,
    DROP COLUMN IF EXISTS baseline_endpoints_total,
    DROP COLUMN IF EXISTS baseline_endpoints_done;
