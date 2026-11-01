CREATE TRIGGER immutable_workflow_event
    BEFORE UPDATE OR DELETE ON review_workflow_events
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
