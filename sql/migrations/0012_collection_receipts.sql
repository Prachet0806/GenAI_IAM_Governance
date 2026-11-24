-- A validated collection outcome is durable before publication is attempted.
CREATE TABLE collection_receipts (
    run_id TEXT PRIMARY KEY REFERENCES discovery_runs(run_id),
    account_id TEXT NOT NULL,
    source_scope TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    validation_version TEXT NOT NULL,
    principal_count INTEGER NOT NULL CHECK (principal_count >= 0),
    grant_count INTEGER NOT NULL CHECK (grant_count >= 0),
    missing_document_count INTEGER NOT NULL CHECK (missing_document_count >= 0),
    observation_sha256 TEXT NOT NULL,
    coverage TEXT NOT NULL
);
CREATE INDEX idx_collection_receipts_source
    ON collection_receipts(account_id, source_scope, collected_at);
