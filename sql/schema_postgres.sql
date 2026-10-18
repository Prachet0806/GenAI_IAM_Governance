-- sql/schema_postgres.sql
-- Postgres-specific statements layered on top of schema_base.sql
-- Idempotent: safe to re-run (DO blocks guard non-IF-NOT-EXISTS DDL).

DO $$
BEGIN
    -- Normalize timestamps to TIMESTAMPTZ (only if not already timestamptz)
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'created_at'
          AND udt_name <> 'timestamptz'
    ) THEN
        ALTER TABLE users ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'campaigns' AND column_name = 'created_at'
          AND udt_name <> 'timestamptz'
    ) THEN
        ALTER TABLE campaigns ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'access_reviews' AND column_name = 'created_at'
          AND udt_name <> 'timestamptz'
    ) THEN
        ALTER TABLE access_reviews
            ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at::timestamptz;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'access_reviews' AND column_name = 'reviewed_at'
          AND udt_name <> 'timestamptz'
    ) THEN
        ALTER TABLE access_reviews
            ALTER COLUMN reviewed_at TYPE TIMESTAMPTZ USING reviewed_at::timestamptz;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'access_reviews' AND column_name = 'remediated_at'
          AND udt_name <> 'timestamptz'
    ) THEN
        ALTER TABLE access_reviews
            ALTER COLUMN remediated_at TYPE TIMESTAMPTZ USING remediated_at::timestamptz;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_logs' AND column_name = 'timestamp'
          AND udt_name <> 'timestamptz'
    ) THEN
        ALTER TABLE audit_logs
            ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp::timestamptz;
    END IF;
    -- Backfill NULL risk_level before enforcing NOT NULL
    UPDATE roles SET risk_level = 'LOW' WHERE risk_level IS NULL;
    -- Enforce NOT NULL only if no NULLs remain
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'roles' AND column_name = 'risk_level' AND is_nullable = 'YES'
    ) AND NOT EXISTS (SELECT 1 FROM roles WHERE risk_level IS NULL) THEN
        ALTER TABLE roles ALTER COLUMN risk_level SET NOT NULL;
    END IF;
    -- Convert audit details to JSONB only when convertible
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_logs' AND column_name = 'details'
          AND udt_name <> 'jsonb'
    ) THEN
        BEGIN
            ALTER TABLE audit_logs
                ALTER COLUMN details TYPE JSONB USING NULLIF(details, '')::jsonb;
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'audit_logs.details not convertible to JSONB; leaving as TEXT';
        END;
    END IF;
END
$$;

ALTER TABLE access_reviews
    ADD COLUMN IF NOT EXISTS ai_risk_summary TEXT;
ALTER TABLE roles ADD COLUMN IF NOT EXISTS policy_document TEXT;
ALTER TABLE roles ADD COLUMN IF NOT EXISTS observed_at TIMESTAMPTZ;
ALTER TABLE access_reviews ADD COLUMN IF NOT EXISTS reviewer_sub TEXT;
ALTER TABLE remediation_approvals ADD COLUMN IF NOT EXISTS discovery_run_id TEXT;
ALTER TABLE remediation_claims ADD COLUMN IF NOT EXISTS fencing_token INTEGER NOT NULL DEFAULT 0;

-- Indexes (idempotent)
CREATE INDEX IF NOT EXISTS idx_reviews_status ON access_reviews(status);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(role_name);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_action_ts ON audit_logs(action, timestamp);

