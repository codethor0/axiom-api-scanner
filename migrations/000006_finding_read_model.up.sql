-- Separate assessed tier from declared rule confidence; drop ambiguous column reuse.
ALTER TABLE findings
    ADD COLUMN assessment_tier TEXT NOT NULL DEFAULT 'tentative',
    ADD COLUMN rule_declared_confidence TEXT NOT NULL DEFAULT '';

UPDATE findings
SET assessment_tier = finding_status
WHERE finding_status IN ('confirmed', 'tentative', 'incomplete');

UPDATE findings
SET assessment_tier = confidence
WHERE confidence IN ('confirmed', 'tentative', 'incomplete')
  AND assessment_tier = 'tentative';

UPDATE findings
SET rule_declared_confidence = lower(trim(confidence))
WHERE lower(trim(confidence)) IN ('high', 'medium', 'low');

UPDATE findings f
SET rule_declared_confidence = lower(trim(spec.v))
FROM (
    SELECT id,
           evidence_summary::jsonb->>'rule_declared_confidence' AS v
    FROM findings
    WHERE evidence_summary IS NOT NULL
      AND evidence_summary <> ''
      AND evidence_summary <> '{}'
) spec
WHERE f.id = spec.id
  AND spec.v IS NOT NULL
  AND lower(trim(spec.v)) IN ('high', 'medium', 'low')
  AND trim(f.rule_declared_confidence) = '';

ALTER TABLE findings
    DROP COLUMN confidence,
    DROP COLUMN finding_status;
