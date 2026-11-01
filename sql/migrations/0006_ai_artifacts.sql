-- Durable advisory explanation jobs and immutable validated artifacts.
CREATE TABLE ai_jobs (
    job_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    task_type TEXT NOT NULL CHECK (task_type='REVIEW_EXPLANATION'),
    review_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    risk_assessment_id TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING','RUNNING','SUCCEEDED','FALLBACK','FAILED')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    run_after TIMESTAMP NOT NULL,
    lease_token TEXT,
    lease_expires_at TIMESTAMP,
    last_error_code TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY(review_id) REFERENCES access_reviews(review_id),
    FOREIGN KEY(snapshot_id) REFERENCES published_snapshots(snapshot_id),
    FOREIGN KEY(observation_id) REFERENCES grant_observations(observation_id),
    FOREIGN KEY(risk_assessment_id) REFERENCES grant_risk_assessments(assessment_id)
);
CREATE INDEX idx_ai_jobs_pending ON ai_jobs(status,run_after,lease_expires_at);
CREATE INDEX idx_ai_jobs_review ON ai_jobs(review_id,created_at);

CREATE TABLE ai_artifacts (
    artifact_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE,
    task_type TEXT NOT NULL CHECK (task_type='REVIEW_EXPLANATION'),
    review_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    risk_assessment_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('MODEL','FALLBACK')),
    validation_status TEXT NOT NULL CHECK (validation_status='VALIDATED'),
    provider TEXT,
    model TEXT,
    prompt_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    output_sha256 TEXT NOT NULL,
    output_json TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    latency_ms INTEGER NOT NULL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cost_usd TEXT,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY(job_id) REFERENCES ai_jobs(job_id),
    FOREIGN KEY(review_id) REFERENCES access_reviews(review_id),
    FOREIGN KEY(snapshot_id) REFERENCES published_snapshots(snapshot_id),
    FOREIGN KEY(observation_id) REFERENCES grant_observations(observation_id),
    FOREIGN KEY(risk_assessment_id) REFERENCES grant_risk_assessments(assessment_id)
);
CREATE INDEX idx_ai_artifacts_review ON ai_artifacts(review_id,created_at);

CREATE TABLE ai_attempts (
    attempt_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('MODEL_SUCCESS','RETRY','FALLBACK','FAILED')),
    error_code TEXT,
    latency_ms INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL,
    UNIQUE(job_id,attempt_number),
    FOREIGN KEY(job_id) REFERENCES ai_jobs(job_id)
);

ALTER TABLE review_decision_events ADD COLUMN ai_artifact_id TEXT
    REFERENCES ai_artifacts(artifact_id);
