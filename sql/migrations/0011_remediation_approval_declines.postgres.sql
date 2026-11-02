CREATE TRIGGER immutable_remediation_decline_update
    BEFORE UPDATE ON remediation_approval_declines
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
CREATE TRIGGER immutable_remediation_decline_delete
    BEFORE DELETE ON remediation_approval_declines
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
CREATE TRIGGER immutable_campaign_reviewer_event_update
    BEFORE UPDATE ON campaign_reviewer_events
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
CREATE TRIGGER immutable_campaign_reviewer_event_delete
    BEFORE DELETE ON campaign_reviewer_events
    FOR EACH ROW EXECUTE FUNCTION reject_evidence_change();
