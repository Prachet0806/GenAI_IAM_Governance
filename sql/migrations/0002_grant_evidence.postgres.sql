ALTER TABLE discovery_runs ADD COLUMN account_id TEXT;
ALTER TABLE discovery_runs ADD COLUMN source_scope TEXT;
CREATE INDEX idx_discovery_runs_source
    ON discovery_runs(account_id, source_scope, started_at);

CREATE FUNCTION reject_evidence_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'published evidence is immutable';
END
$$;
CREATE TRIGGER immutable_published_snapshots
    BEFORE UPDATE OR DELETE ON published_snapshots
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
CREATE TRIGGER immutable_grant_observations
    BEFORE UPDATE OR DELETE ON grant_observations
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
CREATE TRIGGER immutable_grant_paths
    BEFORE UPDATE OR DELETE ON grant_paths
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
