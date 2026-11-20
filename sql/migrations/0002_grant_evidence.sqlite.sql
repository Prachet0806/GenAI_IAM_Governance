ALTER TABLE discovery_runs ADD COLUMN account_id TEXT;
ALTER TABLE discovery_runs ADD COLUMN source_scope TEXT;
CREATE INDEX idx_discovery_runs_source
    ON discovery_runs(account_id, source_scope, started_at);

CREATE TRIGGER immutable_published_snapshots_update
    BEFORE UPDATE ON published_snapshots BEGIN
    SELECT RAISE(ABORT, 'published snapshots are immutable');
END;
CREATE TRIGGER immutable_published_snapshots_delete
    BEFORE DELETE ON published_snapshots BEGIN
    SELECT RAISE(ABORT, 'published snapshots are immutable');
END;
CREATE TRIGGER immutable_grant_observations_update
    BEFORE UPDATE ON grant_observations BEGIN
    SELECT RAISE(ABORT, 'grant observations are immutable');
END;
CREATE TRIGGER immutable_grant_observations_delete
    BEFORE DELETE ON grant_observations BEGIN
    SELECT RAISE(ABORT, 'grant observations are immutable');
END;
CREATE TRIGGER immutable_grant_paths_update
    BEFORE UPDATE ON grant_paths BEGIN
    SELECT RAISE(ABORT, 'grant paths are immutable');
END;
CREATE TRIGGER immutable_grant_paths_delete
    BEFORE DELETE ON grant_paths BEGIN
    SELECT RAISE(ABORT, 'grant paths are immutable');
END;
