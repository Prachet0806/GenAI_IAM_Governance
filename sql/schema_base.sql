-- sql/schema_base.sql
-- Portable base schema (SQLite/Postgres compatible types)

CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    user_name TEXT NOT NULL,
    arn TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
    role_id TEXT PRIMARY KEY,
    role_name TEXT NOT NULL,
    risk_level TEXT CHECK (risk_level IN ('LOW','MEDIUM','HIGH')) DEFAULT 'LOW',
    policy_document TEXT,
    observed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS campaign_reviewers (
    campaign_id TEXT NOT NULL,
    reviewer_sub TEXT NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by TEXT NOT NULL,
    PRIMARY KEY (campaign_id, reviewer_sub),
    FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY(user_id) REFERENCES users(user_id),
    FOREIGN KEY(role_id) REFERENCES roles(role_id)
);

CREATE TABLE IF NOT EXISTS access_reviews (
    review_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    status TEXT CHECK (status IN ('PENDING','APPROVED','REVOKED')) DEFAULT 'PENDING',
    reviewer_comment TEXT,
    reviewer_sub TEXT,
    ai_risk_summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP,
    remediated_at TIMESTAMP,
    CHECK (
        status != 'REVOKED' OR (
            reviewer_comment IS NOT NULL AND reviewer_comment != ''
        )
    ),
    FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id),
    FOREIGN KEY(user_id) REFERENCES users(user_id),
    FOREIGN KEY(role_id) REFERENCES roles(role_id)
);

CREATE TABLE IF NOT EXISTS remediation_approvals (
    approval_id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL UNIQUE,
    approver_sub TEXT NOT NULL,
    approved_at TIMESTAMP NOT NULL,
    discovery_run_id TEXT,
    FOREIGN KEY(review_id) REFERENCES access_reviews(review_id)
);

CREATE TABLE IF NOT EXISTS remediation_claims (
    review_id TEXT PRIMARY KEY,
    claim_token TEXT NOT NULL,
    lease_expires_at TIMESTAMP NOT NULL,
    fencing_token INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(review_id) REFERENCES access_reviews(review_id)
);

CREATE TABLE IF NOT EXISTS governance_mutex (
    lock_name TEXT PRIMARY KEY,
    lock_version INTEGER NOT NULL DEFAULT 0
);
INSERT INTO governance_mutex (lock_name, lock_version)
VALUES ('inventory_remediation', 0) ON CONFLICT(lock_name) DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    level TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    status TEXT,
    message TEXT,
    details TEXT
);

CREATE TABLE IF NOT EXISTS discovery_runs (
    run_id TEXT PRIMARY KEY,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    status TEXT NOT NULL CHECK (status IN ('RUNNING','COMPLETE','INCOMPLETE','FAILED')),
    source TEXT NOT NULL,
    users_seen INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    details TEXT
);

CREATE TABLE IF NOT EXISTS risk_assessments (
    role_id TEXT PRIMARY KEY,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW','MEDIUM','HIGH','UNKNOWN')),
    reason TEXT NOT NULL,
    evidence TEXT,
    rule_version TEXT NOT NULL,
    assessed_at TIMESTAMP NOT NULL,
    FOREIGN KEY(role_id) REFERENCES roles(role_id)
);

CREATE TABLE IF NOT EXISTS ai_generations (
    generation_id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('MODEL','FALLBACK')),
    status TEXT NOT NULL,
    model TEXT,
    prompt_version TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    output_sha256 TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY(review_id) REFERENCES access_reviews(review_id)
);
CREATE INDEX IF NOT EXISTS idx_ai_generations_review ON ai_generations(review_id, created_at);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_reviews_status ON access_reviews(status);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(role_name);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_action_ts ON audit_logs(action, timestamp);
-- Prevent duplicate review rows for the same entitlement in one campaign,
-- and duplicate PENDING reviews across campaigns (race-safe dedupe).
CREATE UNIQUE INDEX IF NOT EXISTS uq_reviews_user_role_campaign
    ON access_reviews(user_id, role_id, campaign_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_reviews_pending_user_role
    ON access_reviews(user_id, role_id) WHERE status = 'PENDING';

