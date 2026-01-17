#sql/schema_base.sql
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
    risk_level TEXT CHECK (risk_level IN ('LOW','MEDIUM','HIGH')) DEFAULT 'LOW'
);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

-- Indexes
CREATE INDEX IF NOT EXISTS idx_reviews_status ON access_reviews(status);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(role_name);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_action_ts ON audit_logs(action, timestamp);

