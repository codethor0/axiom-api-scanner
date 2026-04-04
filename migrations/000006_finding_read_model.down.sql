-- Best-effort revert (does not restore pre-migration confidence vs status semantics).
ALTER TABLE findings
    ADD COLUMN confidence TEXT NOT NULL DEFAULT 'tentative',
    ADD COLUMN finding_status TEXT NOT NULL DEFAULT 'tentative';

UPDATE findings
SET confidence = assessment_tier,
    finding_status = assessment_tier;

ALTER TABLE findings
    DROP COLUMN assessment_tier,
    DROP COLUMN rule_declared_confidence;
