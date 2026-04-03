ALTER TABLE findings
    ADD COLUMN evidence_summary TEXT NOT NULL DEFAULT '{}';
