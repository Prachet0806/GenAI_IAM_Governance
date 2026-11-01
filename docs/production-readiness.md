# Production readiness and operating boundaries

This repository remains a prototype. The safeguards below are enforced by the application where possible; the deployment environment must provide trusted authentication, secret management, IAM permissions, network policy, and durable storage.

## Identity discovery

- Source-scoped discovery covers IAM users and group-derived policies, IAM role managed/inline policies and trust policies, and Identity Center account assignments. Identity Center group assignments remain group paths; members and effective user access are not inferred. Permission boundaries, SCPs, resource policies, and full effective permissions remain unassessed.
- The discovery process fetches each managed policy's default version. Its AWS principal needs `iam:ListUsers`, `iam:ListAttachedUserPolicies`, `iam:ListGroupsForUser`, `iam:ListAttachedGroupPolicies`, `iam:ListUserPolicies`, `iam:GetUserPolicy`, `iam:ListGroupPolicies`, `iam:GetGroupPolicy`, `iam:GetPolicy`, and `iam:GetPolicyVersion`.
- A discovery run is complete only when all users and policy documents are read and processed. Attempts are keyed by AWS account and source scope. Real IAM user and role scans require `AWS_ACCOUNT_ID` before calling STS, then verify the credentials against that account; this lets an STS failure block the intended source. An incomplete, failed, or superseded attempt cannot replace the last published snapshot; a newer nonpublished attempt blocks new campaigns and live remediation for that source until a successful scan publishes a new snapshot.
- A complete run means complete only for its declared source scope. The role and Identity Center scanners publish independently. Unresolved Identity Center customer managed policy references are retained as `MISSING` policy evidence and assessed HIGH while known inline/managed statements remain in the observation; coverage includes the count and unassessed surfaces. `GET /sources/{account_id}/coverage` exposes the published snapshot, newest attempt, and campaign eligibility to campaign administrators.

## Risk evaluation

- Append-only policy risk assessments reference a snapshot and policy hash. Separate grant-path assessments reference exact grant observations; neither record claims the principal's complete effective access. Action wildcards anywhere in the action name, broad actions, and policy conditions require high-risk/manual review handling.
- Missing or malformed policy evidence is escalated to HIGH rather than silently treated as LOW.
- Role trust is classified separately; broad, external, or conditional trust is HIGH. This is not a complete AWS policy simulator. Conditions, cross-account trust semantics, boundaries, organization controls, and resource policies are not resolved into effective access.

## Reviewer identity and authorization

- `scripts/review.py` requires `MOCK_IAM=true` and a pinned `MOCK` snapshot for any decision. It rejects AWS-sourced and legacy/unpinned reviews, and its `LOCAL_DEMO` decision events cannot authorize live remediation. Real decisions go through `api.review_service` and are recorded with `OIDC_API` origin. Pre-migration events are `LEGACY_UNVERIFIED` and cannot authorize live remediation.
- The API validates OIDC JWT signatures against the configured HTTPS JWKS endpoint and requires issuer, audience, expiry, subject, and configured reviewer-group membership. Campaign admins manage a reviewer pool and individual assignments. Reviewers see only their campaign's unassigned work or reviews assigned to them. Decisions require an OPEN campaign and no open exception.
- Campaigns carry owner, account/source scope, deadline, and OPEN/PAUSED/CLOSED state. Assignment, reassignment, deadline, owner, exception, and state changes have append-only workflow events. The event API is paged with `limit` and `offset`; exports include the complete event fields. Duplicate active campaigns for one snapshot are rejected, and grant conflicts roll back creation. Closing requires no pending reviews or open exceptions; closed campaigns cannot reopen. Deadlines are surfaced for tracking; escalation remains an operational responsibility.
- Configure `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, `OIDC_GROUP_CLAIM`, `REVIEWER_GROUP`, `CAMPAIGN_ADMIN_GROUP`, and `REMEDIATION_APPROVER_GROUP`. Use short-lived access tokens, a TLS-terminating gateway, and restricted network access. Never put raw tokens in logs.
- The API does not yet provide organization or entitlement-level rules beyond campaign assignment, nor rate limiting, WAF protection, or deployment infrastructure. Add those controls at the gateway and service before production exposure.
- Keep simulated `auto-demo` decisions out of production databases.
- New campaigns and reviews are pinned to a published snapshot, grant path, observation, and risk assessment. Legacy reviews remain labelled `legacy_unknown_path`; their historical policy evidence cannot be reconstructed.

## GenAI controls

- GenAI is disabled by default. A provider call requires `ENABLE_GENAI=true`, `AI_PROVIDER_DATA_APPROVED=true`, a secret `AI_PSEUDONYM_KEY`, and `GOOGLE_API_KEY`. The data-approval flag must follow review of provider, region, retention, and processing terms. No real provider or privacy review is established by local tests.
- New jobs use frozen rule evidence, policy hashes, redacted resource strings, and HMAC subject references; full policy documents and raw principal names are excluded from provider inputs. Risk evidence can still be sensitive. Provider failures or invalid citations retry with a bounded lease and eventually yield a labelled fallback. Jobs pin their provider model, and an admin may queue an audited next-generation retry of a `FAILED` job while the review remains eligible.
- Validated, immutable `ai_artifacts` are authoritative for explanations. `access_reviews.ai_risk_summary` and `ai_generations` are read-only legacy compatibility data in reviewer projections, exports, and CLI. Decisions record the selected artifact ID; AI workers do not change decisions, approvals, or remediation state.
- Provision a separate Postgres worker role with SELECT only on pinned review/evidence tables and INSERT/UPDATE only on `ai_jobs`, INSERT on `ai_artifacts` and `ai_attempts`. Deny UPDATE/DELETE on `access_reviews`, `review_decision_events`, and `remediation_approvals`. The repository does not provision this deployment role.
- Keep brief, Q&A, and campaign insight tasks disabled until the explanation quality gates in [AI quality gates](ai-quality-gates.md) pass with a controlled provider evaluation.

## Remediation

- Production live detachment remains blocked until the service is deployed and staging acceptance is complete. In non-production, live detachment requires `DRY_RUN=false`, `ENABLE_REMEDIATION=true`, `ALLOW_LIVE_REMEDIATION=true`, a non-empty exact-match `REMEDIATION_ALLOWLIST`, and an independent authenticated approval from someone other than the reviewer. Denylist rules remain in effect; mock mode can never detach.
- A live run requires a fresh complete published AWS snapshot for the review's account and scope, no newer nonpublished attempt for that source, and an independent approval bound to the same pinned snapshot. A per-review lease has a monotonically increasing fencing token and is renewed/checked immediately before detachment. A transaction-level database mutex serializes discovery start/publication against final remediation checks and the AWS call. The worker only detaches direct managed user-policy paths. It verifies current principal ID/ARN, direct attachment, review state, grant observation, approval, snapshot, and lease, then checks the direct attachment is absent after detach. A group-derived path may still provide similar access; the worker does not claim the principal lost effective access. If a process fails after AWS detaches but before persistence, a retry can reconcile the already-absent direct attachment.
- A newer successful snapshot requires a new pinned review and approval. Legacy reviews are not eligible for live remediation.
- Use separate least-privilege AWS roles for discovery and remediation. Do not grant detach permissions to discovery or review services.
- Keep live remediation disabled until staging acceptance and approval are complete.

## Database and audit artifacts

- Apply schema migrations before running the pipeline. SQLite uses a busy timeout; production Postgres requires managed credentials, TLS, backups, and restricted network access.
- Audit exports use unique run IDs, include frozen snapshot/grant/risk evidence, source coverage, AI authority/artifact hash/citations, and decision/workflow events, plus a manifest with artifact hashes. Legacy rows explicitly disclose missing provenance. S3 upload failures are surfaced as failures; configure bucket versioning/retention and least-privilege write access outside this application.
- Operational logs are not a substitute for a protected, append-only audit store. Restrict database update/delete permissions and configure retention at the storage layer.

## Deployment still required

No Lambda packaging, scheduler/event source, infrastructure-as-code, production identity-provider adapter, or runtime secret integration is defined in this repository. AI jobs are durable in the database, but a deployment must invoke the worker, monitor retry/FAILED states, and define timeouts, concurrency, alarms, and independent kill switches for AI and remediation. Do not infer production readiness from a successful local demo.
