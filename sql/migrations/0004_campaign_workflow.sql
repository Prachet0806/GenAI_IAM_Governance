-- Campaign lifecycle and reviewer work allocation. Existing campaigns remain OPEN.
ALTER TABLE campaigns ADD COLUMN account_id TEXT;
ALTER TABLE campaigns ADD COLUMN source_scope TEXT;
ALTER TABLE campaigns ADD COLUMN owner_sub TEXT;
ALTER TABLE campaigns ADD COLUMN due_at TIMESTAMP;
ALTER TABLE campaigns ADD COLUMN state TEXT NOT NULL DEFAULT 'OPEN'
    CHECK (state IN ('OPEN','PAUSED','CLOSED'));
ALTER TABLE campaigns ADD COLUMN closed_at TIMESTAMP;

ALTER TABLE access_reviews ADD COLUMN assigned_reviewer_sub TEXT;
ALTER TABLE access_reviews ADD COLUMN due_at TIMESTAMP;
ALTER TABLE access_reviews ADD COLUMN exception_state TEXT NOT NULL DEFAULT 'NONE'
    CHECK (exception_state IN ('NONE','OPEN','RESOLVED'));

CREATE TABLE review_workflow_events (
    event_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    review_id TEXT,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'CAMPAIGN_CREATED','CAMPAIGN_STATE_CHANGED','CAMPAIGN_OWNER_CHANGED',
        'CAMPAIGN_DEADLINE_CHANGED','CAMPAIGN_REVIEWER_ADDED',
        'REVIEW_ASSIGNED','REVIEW_REASSIGNED','REVIEW_DEADLINE_CHANGED',
        'EXCEPTION_OPENED','EXCEPTION_RESOLVED'
    )),
    actor_sub TEXT NOT NULL,
    previous_value TEXT,
    new_value TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id),
    FOREIGN KEY(review_id) REFERENCES access_reviews(review_id)
);
CREATE INDEX idx_review_workflow_events_campaign
    ON review_workflow_events(campaign_id, created_at);
CREATE INDEX idx_review_workflow_events_review
    ON review_workflow_events(review_id, created_at);
CREATE INDEX idx_reviews_assignee_queue
    ON access_reviews(assigned_reviewer_sub, status, due_at);
