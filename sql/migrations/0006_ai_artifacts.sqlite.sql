CREATE TRIGGER immutable_ai_artifact_update
    BEFORE UPDATE ON ai_artifacts BEGIN
    SELECT RAISE(ABORT, 'AI artifacts are immutable');
END;
CREATE TRIGGER immutable_ai_artifact_delete
    BEFORE DELETE ON ai_artifacts BEGIN
    SELECT RAISE(ABORT, 'AI artifacts are immutable');
END;
CREATE TRIGGER immutable_ai_attempt_update
    BEFORE UPDATE ON ai_attempts BEGIN
    SELECT RAISE(ABORT, 'AI attempts are immutable');
END;
CREATE TRIGGER immutable_ai_attempt_delete
    BEFORE DELETE ON ai_attempts BEGIN
    SELECT RAISE(ABORT, 'AI attempts are immutable');
END;
