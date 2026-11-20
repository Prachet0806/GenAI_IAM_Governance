CREATE TRIGGER immutable_remediation_decline_update
    BEFORE UPDATE ON remediation_approval_declines BEGIN
    SELECT RAISE(ABORT, 'remediation approval declines are immutable');
END;
CREATE TRIGGER immutable_remediation_decline_delete
    BEFORE DELETE ON remediation_approval_declines BEGIN
    SELECT RAISE(ABORT, 'remediation approval declines are immutable');
END;
CREATE TRIGGER immutable_campaign_reviewer_event_update
    BEFORE UPDATE ON campaign_reviewer_events BEGIN
    SELECT RAISE(ABORT, 'campaign reviewer events are immutable');
END;
CREATE TRIGGER immutable_campaign_reviewer_event_delete
    BEFORE DELETE ON campaign_reviewer_events BEGIN
    SELECT RAISE(ABORT, 'campaign reviewer events are immutable');
END;
