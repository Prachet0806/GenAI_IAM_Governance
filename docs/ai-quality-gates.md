# AI explanation release gate

The explanation task is the first task on the AI job/artifact platform. Brief, Q&A, and campaign insight tasks remain disabled until a controlled provider evaluation passes this gate. Local fake-provider tests verify structure and safety behavior; they do not verify a model's factual quality.

## Required evidence

1. Freeze a representative set of at least 100 synthetic or approved, de-identified, snapshot-pinned reviews. Include direct, group-derived, role trust, Identity Center, missing-document, condition, wildcard, and legacy cases. Record snapshot IDs, rule versions, prompt/schema versions, provider model and region, and input hashes.
2. Run the exact deployed worker and model against that set. Two IAM reviewers independently grade whether each explanation is grounded in the frozen rule evidence, states material limitations, and avoids recommending an approval or remediation action. Resolve disagreements before release.
3. Require 100% schema validity, 100% server-resolved citations to the review's own immutable evidence, zero cross-review citations, zero raw principal names/IDs in provider requests, and zero decision/remediation changes by the AI worker. Require at least 95% reviewer agreement that the explanation is factually grounded and at least 95% that material limitations are stated.
4. Re-run duplicate-delivery, expired-lease, provider timeout, malformed output, unavailable document, and disabled-provider cases. Require one accepted artifact per idempotency key and a clearly labelled fallback or failure without blocking human decisions.
5. Record observed latency, token usage, provider failures, fallback rate, and spend for the evaluation. Obtain data-handling and retention approval before any real identity evidence is sent. Capture the exact CI commit and Postgres job result.

Keep `ENABLE_GENAI=false` or `AI_PROVIDER_DATA_APPROVED=false` until the provider/data gate is approved. The repository has no enabled brief, Q&A, or campaign insight task type, and their implementation requires separate task-specific schemas, evidence authorization, privacy review, and evaluations after this gate passes.
