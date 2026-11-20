ALTER TABLE campaigns ADD COLUMN snapshot_id TEXT REFERENCES published_snapshots(snapshot_id);
ALTER TABLE access_reviews ADD COLUMN snapshot_id TEXT REFERENCES published_snapshots(snapshot_id);
ALTER TABLE access_reviews ADD COLUMN grant_id TEXT REFERENCES grant_paths(grant_id);
ALTER TABLE access_reviews ADD COLUMN observation_id TEXT REFERENCES grant_observations(observation_id);
ALTER TABLE access_reviews ADD COLUMN risk_assessment_id TEXT REFERENCES grant_risk_assessments(assessment_id);

DROP INDEX uq_reviews_user_role_campaign;
DROP INDEX uq_reviews_pending_user_role;
CREATE UNIQUE INDEX uq_reviews_legacy_campaign
    ON access_reviews(user_id, role_id, campaign_id) WHERE grant_id IS NULL;
CREATE UNIQUE INDEX uq_reviews_legacy_pending
    ON access_reviews(user_id, role_id) WHERE status='PENDING' AND grant_id IS NULL;
CREATE UNIQUE INDEX uq_reviews_grant_campaign
    ON access_reviews(campaign_id, grant_id) WHERE grant_id IS NOT NULL;
CREATE UNIQUE INDEX uq_reviews_grant_pending
    ON access_reviews(grant_id) WHERE status='PENDING' AND grant_id IS NOT NULL;

CREATE TRIGGER pinned_review_binding_insert
    BEFORE INSERT ON access_reviews
    WHEN (NEW.snapshot_id IS NULL OR NEW.grant_id IS NULL
          OR NEW.observation_id IS NULL OR NEW.risk_assessment_id IS NULL)
      AND (NEW.snapshot_id IS NOT NULL OR NEW.grant_id IS NOT NULL
           OR NEW.observation_id IS NOT NULL OR NEW.risk_assessment_id IS NOT NULL)
    BEGIN SELECT RAISE(ABORT, 'review evidence binding must be complete'); END;
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
CREATE TRIGGER pinned_review_binding_update
    BEFORE UPDATE OF snapshot_id,grant_id,observation_id,risk_assessment_id
    ON access_reviews BEGIN
    SELECT RAISE(ABORT, 'review evidence binding is immutable');
END;

CREATE TRIGGER immutable_policy_risk_update
    BEFORE UPDATE ON policy_risk_assessments BEGIN
    SELECT RAISE(ABORT, 'policy risk assessments are immutable');
END;
CREATE TRIGGER immutable_policy_risk_delete
    BEFORE DELETE ON policy_risk_assessments BEGIN
    SELECT RAISE(ABORT, 'policy risk assessments are immutable');
END;
CREATE TRIGGER immutable_grant_risk_update
    BEFORE UPDATE ON grant_risk_assessments BEGIN
    SELECT RAISE(ABORT, 'grant risk assessments are immutable');
END;
CREATE TRIGGER immutable_grant_risk_delete
    BEFORE DELETE ON grant_risk_assessments BEGIN
    SELECT RAISE(ABORT, 'grant risk assessments are immutable');
END;
CREATE TRIGGER immutable_decision_event_update
    BEFORE UPDATE ON review_decision_events BEGIN
    SELECT RAISE(ABORT, 'review decision events are immutable');
END;
CREATE TRIGGER immutable_decision_event_delete
    BEFORE DELETE ON review_decision_events BEGIN
    SELECT RAISE(ABORT, 'review decision events are immutable');
END;
