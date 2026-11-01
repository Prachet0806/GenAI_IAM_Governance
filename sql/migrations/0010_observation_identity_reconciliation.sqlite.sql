-- Fail the upgrade if an already-pinned review has a mismatched identity.
CREATE TABLE _review_identity_validation (valid INTEGER NOT NULL CHECK (valid=1));
INSERT INTO _review_identity_validation(valid)
SELECT CASE WHEN EXISTS (
    SELECT 1 FROM access_reviews r JOIN grant_paths gp ON gp.grant_id=r.grant_id
    WHERE r.grant_id IS NOT NULL
      AND (r.user_id<>gp.principal_id OR r.role_id<>gp.policy_id)
) THEN 0 ELSE 1 END;
DROP TABLE _review_identity_validation;

DROP TRIGGER pinned_review_binding_matches;
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
          AND gp.principal_id=NEW.user_id
          AND gp.policy_id=NEW.role_id
    )
    BEGIN SELECT RAISE(ABORT, 'review evidence binding does not match'); END;
CREATE TRIGGER pinned_review_identity_update
    BEFORE UPDATE OF user_id,role_id ON access_reviews
    WHEN OLD.snapshot_id IS NOT NULL AND
         (NEW.user_id IS NOT OLD.user_id OR NEW.role_id IS NOT OLD.role_id)
    BEGIN SELECT RAISE(ABORT, 'review identity binding is immutable'); END;

CREATE TRIGGER reconciliation_event_binding
    BEFORE INSERT ON remediation_reconciliation_events
    WHEN NOT EXISTS (
        SELECT 1 FROM remediation_action_events hold
        WHERE hold.event_id=NEW.hold_event_id
          AND hold.review_id=NEW.review_id
          AND hold.event_type='RECONCILIATION_REQUIRED'
          AND hold.snapshot_id=NEW.snapshot_id
          AND hold.grant_id=NEW.grant_id
    ) OR (NEW.event_sequence=2 AND NOT EXISTS (
        SELECT 1 FROM remediation_reconciliation_events request
        WHERE request.request_id=NEW.request_id
          AND request.event_sequence=1
          AND request.hold_event_id=NEW.hold_event_id
          AND request.review_id=NEW.review_id
          AND request.snapshot_id=NEW.snapshot_id
          AND request.grant_id=NEW.grant_id
    ))
    BEGIN SELECT RAISE(ABORT, 'reconciliation event binding does not match'); END;

CREATE TRIGGER immutable_reconciliation_update
    BEFORE UPDATE ON remediation_reconciliation_events BEGIN
    SELECT RAISE(ABORT, 'remediation reconciliation events are immutable');
END;
CREATE TRIGGER immutable_reconciliation_delete
    BEFORE DELETE ON remediation_reconciliation_events BEGIN
    SELECT RAISE(ABORT, 'remediation reconciliation events are immutable');
END;
