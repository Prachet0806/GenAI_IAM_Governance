-- Additive, nullable provider provenance. Old explanation artifacts remain readable.
ALTER TABLE ai_artifacts ADD COLUMN approval_version TEXT;
ALTER TABLE ai_artifacts ADD COLUMN provider_region TEXT;
ALTER TABLE ai_artifacts ADD COLUMN prompt_sha256 TEXT;
ALTER TABLE ai_artifacts ADD COLUMN provider_input_sha256 TEXT;
ALTER TABLE ai_artifacts ADD COLUMN input_classes TEXT;
