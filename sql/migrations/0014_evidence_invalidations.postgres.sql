CREATE TRIGGER immutable_evidence_invalidations
    BEFORE UPDATE OR DELETE ON evidence_invalidations
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
