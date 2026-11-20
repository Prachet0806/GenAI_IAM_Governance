-- SQLite cannot alter a CHECK constraint in place. Preserve parent identity and FKs.
DROP TRIGGER pinned_review_binding_matches;
CREATE TABLE grant_paths_next (
    grant_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    grant_type TEXT NOT NULL CHECK (
        grant_type IN ('DIRECT_MANAGED','DIRECT_INLINE','GROUP_MANAGED','GROUP_INLINE',
                       'ROLE_MANAGED','ROLE_INLINE','ROLE_TRUST',
                       'IDENTITY_CENTER_ASSIGNMENT')
    ),
    source_id TEXT NOT NULL,
    attachment_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    UNIQUE(account_id, principal_id, grant_type, source_id, attachment_id)
);
INSERT INTO grant_paths_next
    SELECT grant_id,account_id,principal_id,principal_arn,grant_type,
           source_id,attachment_id,policy_id FROM grant_paths;
DROP TABLE grant_paths;
ALTER TABLE grant_paths_next RENAME TO grant_paths;
CREATE INDEX idx_grant_paths_principal ON grant_paths(account_id,principal_id);
CREATE TRIGGER immutable_grant_paths_update
    BEFORE UPDATE ON grant_paths BEGIN
    SELECT RAISE(ABORT, 'grant paths are immutable');
END;
CREATE TRIGGER immutable_grant_paths_delete
    BEFORE DELETE ON grant_paths BEGIN
    SELECT RAISE(ABORT, 'grant paths are immutable');
END;
CREATE TRIGGER pinned_review_binding_matches
    BEFORE INSERT ON access_reviews
    WHEN NEW.snapshot_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM grant_observations go
        JOIN grant_risk_assessments gra
          ON gra.observation_id=go.observation_id
             AND gra.assessment_id=NEW.risk_assessment_id
        JOIN grant_paths gp ON gp.grant_id=go.grant_id
        JOIN published_snapshots ps ON ps.snapshot_id=go.snapshot_id
             AND ps.account_id=gp.account_id
        JOIN policy_risk_assessments pra ON pra.assessment_id=gra.policy_assessment_id
             AND pra.snapshot_id=go.snapshot_id
             AND pra.policy_id=gp.policy_id
             AND pra.policy_sha256=go.policy_sha256
        JOIN campaigns c ON c.campaign_id=NEW.campaign_id
        WHERE go.observation_id=NEW.observation_id
          AND go.snapshot_id=NEW.snapshot_id
          AND go.grant_id=NEW.grant_id
          AND c.snapshot_id=NEW.snapshot_id
    )
    BEGIN SELECT RAISE(ABORT, 'review evidence binding does not match'); END;
