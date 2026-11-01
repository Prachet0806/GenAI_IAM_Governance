CREATE TRIGGER immutable_remediation_approval_event
    BEFORE UPDATE OR DELETE ON remediation_approval_events
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
CREATE TRIGGER immutable_remediation_action_event
    BEFORE UPDATE OR DELETE ON remediation_action_events
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
