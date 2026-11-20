-- Policy risk and grant-path risk are separate append-only records.
CREATE TABLE policy_risk_assessments (
    assessment_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW','MEDIUM','HIGH','UNKNOWN')),
    reason TEXT NOT NULL,
    evidence TEXT NOT NULL,
    assessed_at TIMESTAMP NOT NULL,
    UNIQUE(snapshot_id, policy_id, policy_sha256, rule_version),
    FOREIGN KEY(snapshot_id) REFERENCES published_snapshots(snapshot_id)
);

CREATE TABLE grant_risk_assessments (
    assessment_id TEXT PRIMARY KEY,
    observation_id TEXT NOT NULL,
    policy_assessment_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW','MEDIUM','HIGH','UNKNOWN')),
    reason TEXT NOT NULL,
    assessment_scope TEXT NOT NULL DEFAULT 'GRANT_PATH'
        CHECK (assessment_scope = 'GRANT_PATH'),
    assessed_at TIMESTAMP NOT NULL,
    UNIQUE(observation_id, rule_version),
    FOREIGN KEY(observation_id) REFERENCES grant_observations(observation_id),
    FOREIGN KEY(policy_assessment_id) REFERENCES policy_risk_assessments(assessment_id)
);

CREATE TABLE review_decision_events (
    event_id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL,
    snapshot_id TEXT,
    grant_id TEXT,
    observation_id TEXT,
    risk_assessment_id TEXT,
    decision TEXT NOT NULL CHECK (decision IN ('APPROVED','REVOKED')),
    reviewer_sub TEXT,
    reviewer_comment TEXT NOT NULL,
    decided_at TIMESTAMP NOT NULL,
    FOREIGN KEY(review_id) REFERENCES access_reviews(review_id)
);
CREATE INDEX idx_review_decision_events_review
    ON review_decision_events(review_id, decided_at);
