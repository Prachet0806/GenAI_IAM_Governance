# Production readiness and operating boundaries

This repository remains a prototype. The safeguards below are enforced by the application where possible; the deployment environment must provide trusted authentication, secret management, IAM permissions, network policy, and durable storage.

## Identity discovery

- Current discovery covers IAM users, direct managed and inline policies, group membership, and managed/inline policies attached to those groups. It does not cover IAM roles and trust relationships, Identity Center, permission boundaries, SCPs, or resource policies.
- The discovery process fetches each managed policy's default version. Its AWS principal needs `iam:ListUsers`, `iam:ListAttachedUserPolicies`, `iam:ListGroupsForUser`, `iam:ListAttachedGroupPolicies`, `iam:ListUserPolicies`, `iam:GetUserPolicy`, `iam:ListGroupPolicies`, `iam:GetGroupPolicy`, `iam:GetPolicy`, and `iam:GetPolicyVersion`.
- A discovery run is complete only when all users and policy documents are read and processed. An incomplete or failed run must not replace the current entitlement links. Historical discovery run status is retained.
- A complete run means complete only for the declared user/group policy scope. Add the remaining identity sources and effective-permission semantics before treating the inventory as complete for an AWS account.

## Risk evaluation

- Risk assessments include the policy document evidence and rule version. Broad actions and policy conditions require high-risk/manual review handling.
- Missing or malformed policy evidence is escalated to HIGH rather than silently treated as LOW.
- This is not a complete AWS policy simulator. Conditions, cross-account trust, boundaries, organization controls, and resource policies remain outside the current evaluator.

## Reviewer identity and authorization

- `scripts/review.py` is restricted to decision-making on `MOCK_IAM=true` demo data. Real decisions go through `api.review_service`.
- The API validates OIDC JWT signatures against the configured HTTPS JWKS endpoint and requires issuer, audience, expiry, subject, and configured reviewer-group membership. Campaign admins assign reviewer subjects; decisions require an explicit campaign assignment.
- Configure `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, `OIDC_GROUP_CLAIM`, `REVIEWER_GROUP`, `CAMPAIGN_ADMIN_GROUP`, and `REMEDIATION_APPROVER_GROUP`. Use short-lived access tokens, a TLS-terminating gateway, and restricted network access. Never put raw tokens in logs.
- The API does not yet provide organization or entitlement-level rules beyond campaign assignment, nor rate limiting, WAF protection, or deployment infrastructure. Add those controls at the gateway and service before production exposure.
- Keep simulated `auto-demo` decisions out of production databases.

## GenAI controls

- GenAI is disabled by default. To enable it, explicitly set `ENABLE_GENAI=true` and provide `GOOGLE_API_KEY` through a secret manager.
- Before enabling it with real identity data, approve provider, region, retention, and data-processing requirements. Inputs pseudonymize the user and contain policy and risk evidence; policy documents are still sensitive data.
- AI output is advisory and stored as an append-only generation with source, model, prompt version, input/output hashes, and timestamp. The reviewer decision remains independent.
- Disable the feature by setting `ENABLE_GENAI=false`; provider failures produce a labeled deterministic fallback for eligible reviews.

## Remediation

- Production live detachment remains blocked until the service is deployed and staging acceptance is complete. In non-production, live detachment requires `DRY_RUN=false`, `ENABLE_REMEDIATION=true`, `ALLOW_LIVE_REMEDIATION=true`, a non-empty exact-match `REMEDIATION_ALLOWLIST`, and an independent authenticated approval from someone other than the reviewer. Denylist rules remain in effect; mock mode can never detach.
- A live run requires the latest scan to be complete, within `MAX_DISCOVERY_AGE_HOURS` (default 24, maximum 168), and from the supported user/group policy scope. The worker only detaches direct managed user policies and skips group-derived or inline grants. Each direct policy is rechecked against AWS immediately before detach.
- Only revoked reviews whose entitlement remains present in the current complete snapshot are eligible.
- Use separate least-privilege AWS roles for discovery and remediation. Do not grant detach permissions to discovery or review services.
- Keep live remediation disabled until staging acceptance and approval are complete.

## Database and audit artifacts

- Apply schema migrations before running the pipeline. SQLite uses a busy timeout; production Postgres requires managed credentials, TLS, backups, and restricted network access.
- Audit exports use unique run IDs and include a manifest with artifact hashes. S3 upload failures are surfaced as failures; configure bucket versioning/retention and least-privilege write access outside this application.
- Operational logs are not a substitute for a protected, append-only audit store. Restrict database update/delete permissions and configure retention at the storage layer.

## Deployment still required

No Lambda packaging, event source, scheduler/queue, infrastructure-as-code, production identity-provider adapter, or runtime secret integration is defined in this repository. A deployment must define these explicitly, including timeouts, retry/dead-letter behavior, concurrency, alarms, and independent kill switches for AI and remediation. Do not infer production readiness from a successful local demo.
