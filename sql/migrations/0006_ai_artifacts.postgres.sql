CREATE TRIGGER immutable_ai_artifact
    BEFORE UPDATE OR DELETE ON ai_artifacts
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
CREATE TRIGGER immutable_ai_attempt
    BEFORE UPDATE OR DELETE ON ai_attempts
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
