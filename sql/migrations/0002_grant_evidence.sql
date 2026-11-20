-- Source-scoped discovery history and immutable grant evidence.
CREATE TABLE source_attempt_heads (
    account_id TEXT NOT NULL,
    source_scope TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    PRIMARY KEY (account_id, source_scope),
    FOREIGN KEY(attempt_id) REFERENCES discovery_runs(run_id)
);

CREATE TABLE published_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    source_scope TEXT NOT NULL,
    published_at TIMESTAMP NOT NULL,
    users_seen INTEGER NOT NULL,
    coverage TEXT NOT NULL,
    FOREIGN KEY(snapshot_id) REFERENCES discovery_runs(run_id)
);
CREATE INDEX idx_published_snapshots_source
    ON published_snapshots(account_id, source_scope, published_at);

CREATE TABLE source_publications (
    account_id TEXT NOT NULL,
    source_scope TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    PRIMARY KEY (account_id, source_scope),
    FOREIGN KEY(snapshot_id) REFERENCES published_snapshots(snapshot_id)
);

CREATE TABLE grant_paths (
    grant_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    grant_type TEXT NOT NULL CHECK (
        grant_type IN ('DIRECT_MANAGED','DIRECT_INLINE','GROUP_MANAGED','GROUP_INLINE')
    ),
    source_id TEXT NOT NULL,
    attachment_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    UNIQUE(account_id, principal_id, grant_type, source_id, attachment_id)
);
CREATE INDEX idx_grant_paths_principal ON grant_paths(account_id, principal_id);

CREATE TABLE grant_observations (
    observation_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    principal_name TEXT NOT NULL,
    source_name TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    policy_version TEXT,
    policy_sha256 TEXT NOT NULL,
    policy_document TEXT NOT NULL,
    observed_at TIMESTAMP NOT NULL,
    UNIQUE(snapshot_id, grant_id),
    FOREIGN KEY(snapshot_id) REFERENCES published_snapshots(snapshot_id),
    FOREIGN KEY(grant_id) REFERENCES grant_paths(grant_id)
);
CREATE INDEX idx_grant_observations_snapshot
    ON grant_observations(snapshot_id, grant_id);
