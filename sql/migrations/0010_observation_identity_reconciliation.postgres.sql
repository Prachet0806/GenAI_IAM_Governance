DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM access_reviews r JOIN grant_paths gp ON gp.grant_id=r.grant_id
        WHERE r.grant_id IS NOT NULL
          AND (r.user_id<>gp.principal_id OR r.role_id<>gp.policy_id)
    ) THEN
        RAISE EXCEPTION 'existing review identity binding does not match';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION reject_review_binding_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.snapshot_id IS DISTINCT FROM NEW.snapshot_id
       OR OLD.grant_id IS DISTINCT FROM NEW.grant_id
       OR OLD.observation_id IS DISTINCT FROM NEW.observation_id
       OR OLD.risk_assessment_id IS DISTINCT FROM NEW.risk_assessment_id
       OR (OLD.snapshot_id IS NOT NULL AND
           (OLD.user_id IS DISTINCT FROM NEW.user_id
            OR OLD.role_id IS DISTINCT FROM NEW.role_id)) THEN
        RAISE EXCEPTION 'review evidence binding is immutable';
    END IF;
    RETURN NEW;
END
$$;
CREATE OR REPLACE FUNCTION validate_review_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.snapshot_id IS NOT NULL AND NOT EXISTS (
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
    ) THEN
        RAISE EXCEPTION 'review evidence binding does not match';
    END IF;
    RETURN NEW;
END
$$;
CREATE FUNCTION validate_reconciliation_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
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
    )) THEN
        RAISE EXCEPTION 'reconciliation event binding does not match';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER reconciliation_event_binding
    BEFORE INSERT ON remediation_reconciliation_events
    FOR EACH ROW EXECUTE FUNCTION validate_reconciliation_event();
CREATE TRIGGER immutable_reconciliation_event
    BEFORE UPDATE OR DELETE ON remediation_reconciliation_events
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
