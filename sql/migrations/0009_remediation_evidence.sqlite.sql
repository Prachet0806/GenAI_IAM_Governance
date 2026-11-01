CREATE TRIGGER immutable_remediation_approval_update
    BEFORE UPDATE ON remediation_approval_events BEGIN
    SELECT RAISE(ABORT, 'remediation approval events are immutable');
END;
CREATE TRIGGER immutable_remediation_approval_delete
    BEFORE DELETE ON remediation_approval_events BEGIN
    SELECT RAISE(ABORT, 'remediation approval events are immutable');
END;
CREATE TRIGGER immutable_remediation_action_update
    BEFORE UPDATE ON remediation_action_events BEGIN
    SELECT RAISE(ABORT, 'remediation action events are immutable');
END;
CREATE TRIGGER immutable_remediation_action_delete
    BEFORE DELETE ON remediation_action_events BEGIN
    SELECT RAISE(ABORT, 'remediation action events are immutable');
END;
