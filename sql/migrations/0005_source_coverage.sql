-- Explicit principal/source kinds and missing policy evidence.
ALTER TABLE users ADD COLUMN principal_kind TEXT NOT NULL DEFAULT 'IAM_USER'
    CHECK (principal_kind IN ('IAM_USER','IAM_ROLE','IDENTITY_CENTER_USER','IDENTITY_CENTER_GROUP'));
ALTER TABLE grant_observations ADD COLUMN evidence_status TEXT NOT NULL DEFAULT 'COMPLETE'
    CHECK (evidence_status IN ('COMPLETE','MISSING'));
ALTER TABLE grant_observations ADD COLUMN missing_reason TEXT;
CREATE INDEX idx_grant_observations_evidence_status
    ON grant_observations(snapshot_id,evidence_status);
