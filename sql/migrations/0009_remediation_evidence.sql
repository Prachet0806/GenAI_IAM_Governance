-- The mutable approval row is a lookup projection. These rows are the audit record.
CREATE TABLE remediation_approval_events (
    event_id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL UNIQUE,
    review_id TEXT NOT NULL REFERENCES access_reviews(review_id),
    decision_event_id TEXT NOT NULL REFERENCES review_decision_events(event_id),
    event_type TEXT NOT NULL CHECK (event_type IN ('APPROVED','RENEWED')),
    approver_sub TEXT NOT NULL,
    approved_at TIMESTAMP NOT NULL,
    snapshot_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    risk_assessment_id TEXT NOT NULL,
    grant_type TEXT NOT NULL,
    action_type TEXT NOT NULL
);
CREATE INDEX idx_remediation_approval_events_review
    ON remediation_approval_events(review_id,approved_at);

-- ACTION_REQUESTED is committed before an AWS mutation. An intent without a
-- terminal event is reconciled by reading AWS, never by repeating the mutation.
CREATE TABLE remediation_action_events (
    event_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL,
    review_id TEXT NOT NULL REFERENCES access_reviews(review_id),
    approval_event_id TEXT NOT NULL REFERENCES remediation_approval_events(event_id),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'PREFLIGHT_PASSED','PREFLIGHT_REJECTED','ACTION_REQUESTED',
        'ACTION_VERIFIED','ALREADY_ABSENT','RECONCILIATION_REQUIRED','ABORTED'
    )),
    event_sequence INTEGER NOT NULL CHECK (event_sequence BETWEEN 1 AND 3),
    action_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    UNIQUE(attempt_id,event_type),
    UNIQUE(attempt_id,event_sequence)
);
CREATE INDEX idx_remediation_action_events_review
    ON remediation_action_events(review_id,created_at);
