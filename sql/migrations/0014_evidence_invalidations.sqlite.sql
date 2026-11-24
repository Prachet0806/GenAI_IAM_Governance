CREATE TRIGGER immutable_evidence_invalidation_update
    BEFORE UPDATE ON evidence_invalidations BEGIN
    SELECT RAISE(ABORT, 'evidence invalidations are immutable');
END;
CREATE TRIGGER immutable_evidence_invalidation_delete
    BEFORE DELETE ON evidence_invalidations BEGIN
    SELECT RAISE(ABORT, 'evidence invalidations are immutable');
END;
