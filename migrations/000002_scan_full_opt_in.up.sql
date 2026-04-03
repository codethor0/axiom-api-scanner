ALTER TABLE scans
    ADD COLUMN allow_full_execution BOOLEAN NOT NULL DEFAULT false;
