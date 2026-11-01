-- Old decisions have no verifiable authentication provenance.
ALTER TABLE review_decision_events ADD COLUMN decision_origin TEXT NOT NULL
    DEFAULT 'LEGACY_UNVERIFIED'
    CHECK (decision_origin IN ('LEGACY_UNVERIFIED','OIDC_API','LOCAL_DEMO'));
