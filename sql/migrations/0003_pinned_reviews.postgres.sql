ALTER TABLE campaigns ADD COLUMN snapshot_id TEXT REFERENCES published_snapshots(snapshot_id);
ALTER TABLE access_reviews ADD COLUMN snapshot_id TEXT REFERENCES published_snapshots(snapshot_id);
ALTER TABLE access_reviews ADD COLUMN grant_id TEXT REFERENCES grant_paths(grant_id);
ALTER TABLE access_reviews ADD COLUMN observation_id TEXT REFERENCES grant_observations(observation_id);
ALTER TABLE access_reviews ADD COLUMN risk_assessment_id TEXT REFERENCES grant_risk_assessments(assessment_id);
ALTER TABLE access_reviews ADD CONSTRAINT review_evidence_binding_complete CHECK (
    (snapshot_id IS NULL AND grant_id IS NULL
     AND observation_id IS NULL AND risk_assessment_id IS NULL)
    OR
    (snapshot_id IS NOT NULL AND grant_id IS NOT NULL
     AND observation_id IS NOT NULL AND risk_assessment_id IS NOT NULL)
);

CREATE FUNCTION reject_review_binding_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.snapshot_id IS DISTINCT FROM NEW.snapshot_id
       OR OLD.grant_id IS DISTINCT FROM NEW.grant_id
       OR OLD.observation_id IS DISTINCT FROM NEW.observation_id
       OR OLD.risk_assessment_id IS DISTINCT FROM NEW.risk_assessment_id THEN
        RAISE EXCEPTION 'review evidence binding is immutable';
    END IF;
    RETURN NEW;
END
$$;
CREATE FUNCTION validate_review_binding() RETURNS trigger LANGUAGE plpgsql AS $$
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
    ) THEN
        RAISE EXCEPTION 'review evidence binding does not match';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER pinned_review_binding
    BEFORE UPDATE ON access_reviews
    FOR EACH ROW EXECUTE FUNCTION reject_review_binding_change();
CREATE TRIGGER pinned_review_binding_matches
    BEFORE INSERT ON access_reviews
    FOR EACH ROW EXECUTE FUNCTION validate_review_binding();

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

CREATE TRIGGER immutable_policy_risk
    BEFORE UPDATE OR DELETE ON policy_risk_assessments
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
CREATE TRIGGER immutable_grant_risk
    BEFORE UPDATE OR DELETE ON grant_risk_assessments
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
CREATE TRIGGER immutable_decision_event
    BEFORE UPDATE OR DELETE ON review_decision_events
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
