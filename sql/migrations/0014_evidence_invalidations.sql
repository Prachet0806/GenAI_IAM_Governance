-- An evidence defect is an additive annotation, never a snapshot rewrite.
CREATE TABLE evidence_invalidations (
    invalidation_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES published_snapshots(snapshot_id),
    manifest_sha256 TEXT NOT NULL,
    reason_code TEXT NOT NULL CHECK (
        reason_code IN ('EVIDENCE_DEFECT','SOURCE_CORRECTION','POLICY_DOCUMENT_ERROR')
    ),
    detail TEXT NOT NULL,
    actor_sub TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE INDEX idx_evidence_invalidations_snapshot
    ON evidence_invalidations(snapshot_id, recorded_at);
