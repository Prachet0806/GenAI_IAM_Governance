-- Historical observations remain NULL: a grant path's first-seen ARN cannot
-- establish the ARN seen in an older snapshot.
ALTER TABLE grant_observations ADD COLUMN principal_arn TEXT;

-- An operator authorizes a read-only recheck. A worker records one terminal
-- result for that request under its current lease; neither row is mutable.
CREATE TABLE remediation_reconciliation_events (
    event_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    review_id TEXT NOT NULL REFERENCES access_reviews(review_id),
    hold_event_id TEXT NOT NULL REFERENCES remediation_action_events(event_id),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'REQUESTED','VERIFIED_ABSENT','STILL_PRESENT','UNREADABLE'
    )),
    event_sequence INTEGER NOT NULL CHECK (
        (event_sequence=1 AND event_type='REQUESTED') OR
        (event_sequence=2 AND event_type IN (
            'VERIFIED_ABSENT','STILL_PRESENT','UNREADABLE'
        ))
    ),
    actor_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    fencing_token INTEGER,
    evidence_json TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    UNIQUE(request_id,event_sequence),
    CHECK ((event_sequence=1 AND fencing_token IS NULL) OR
           (event_sequence=2 AND fencing_token IS NOT NULL))
);
CREATE INDEX idx_reconciliation_events_review
    ON remediation_reconciliation_events(review_id,created_at);
