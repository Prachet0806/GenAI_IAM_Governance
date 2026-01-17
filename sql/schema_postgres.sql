#sql/schema_postgres.sql
-- Postgres-specific statements layered on top of schema_base.sql
-- Normalize timestamps to TIMESTAMPTZ and audit details to JSONB.

ALTER TABLE users ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at;
ALTER TABLE roles ALTER COLUMN risk_level SET NOT NULL;
ALTER TABLE campaigns ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at;
ALTER TABLE access_reviews
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at,
    ALTER COLUMN reviewed_at TYPE TIMESTAMPTZ USING reviewed_at,
    ALTER COLUMN remediated_at TYPE TIMESTAMPTZ USING remediated_at;
ALTER TABLE access_reviews
    ADD COLUMN IF NOT EXISTS ai_risk_summary TEXT;
ALTER TABLE audit_logs
    ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp,
    ALTER COLUMN details TYPE JSONB USING details::jsonb;

-- Indexes (idempotent)
CREATE INDEX IF NOT EXISTS idx_reviews_status ON access_reviews(status);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(role_name);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_action_ts ON audit_logs(action, timestamp);

