-- Pin the provider model and retain retry lineage for failed AI jobs.
ALTER TABLE ai_jobs ADD COLUMN provider_model TEXT;
ALTER TABLE ai_jobs ADD COLUMN generation INTEGER NOT NULL DEFAULT 1
    CHECK (generation > 0);
ALTER TABLE ai_jobs ADD COLUMN retry_of_job_id TEXT REFERENCES ai_jobs(job_id);
CREATE INDEX idx_ai_jobs_retry_lineage ON ai_jobs(retry_of_job_id);
CREATE UNIQUE INDEX uq_ai_jobs_retry_parent ON ai_jobs(retry_of_job_id)
    WHERE retry_of_job_id IS NOT NULL;
