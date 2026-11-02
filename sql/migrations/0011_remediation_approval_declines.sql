-- A decline is a separate immutable decision; it never means approval or execution.
ALTER TABLE remediation_approval_events ADD COLUMN approval_reason TEXT NOT NULL DEFAULT '';
CREATE TABLE remediation_approval_declines (
    decline_id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL UNIQUE REFERENCES access_reviews(review_id),
    decision_event_id TEXT NOT NULL REFERENCES review_decision_events(event_id),
    approver_sub TEXT NOT NULL,
    declined_at TIMESTAMP NOT NULL,
    snapshot_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    risk_assessment_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0)
);
CREATE INDEX idx_remediation_declines_time
    ON remediation_approval_declines(declined_at,decline_id);

CREATE TABLE campaign_reviewer_events (
    event_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    reviewer_sub TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('ADDED','REMOVED')),
    actor_sub TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_campaign_reviewer_events
    ON campaign_reviewer_events(campaign_id,created_at,event_id);
