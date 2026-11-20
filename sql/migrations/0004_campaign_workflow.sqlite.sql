CREATE TRIGGER immutable_workflow_event_update
    BEFORE UPDATE ON review_workflow_events BEGIN
    SELECT RAISE(ABORT, 'workflow events are immutable');
END;
CREATE TRIGGER immutable_workflow_event_delete
    BEFORE DELETE ON review_workflow_events BEGIN
    SELECT RAISE(ABORT, 'workflow events are immutable');
END;
