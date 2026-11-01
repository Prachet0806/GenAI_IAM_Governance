# IAM Access Certification Engine

A Python prototype for IAM inventory, entitlement risk assessment, access review campaigns, gated remediation, and audit exports. It supports local SQLite/Postgres and a seeded mock IAM dataset. It is not production-ready; see [production readiness](docs/production-readiness.md) for limitations and required controls.

## Current capabilities

- Discovers IAM user direct/group policy paths, IAM role managed/inline policies and trust paths, and Identity Center account assignment paths in separate account/source scopes. Managed policy documents are fetched where available; unresolved Identity Center customer managed references are marked as missing evidence. Permission boundaries, SCPs, resource policies, group membership expansion in Identity Center, and effective permissions remain outside the declared scopes.
- Records attempts by AWS account and declared source scope. Real IAM user and role scans require `AWS_ACCOUNT_ID` before their first AWS call, then verify it with STS. A complete scan atomically publishes immutable grant-path observations and advances that source's published snapshot; a failed or superseded attempt retains the prior publication for audit but blocks new campaigns and live remediation for that source.
- Keeps direct, user-inline, and each group-derived path distinct. Grant identity uses account, principal, grant type, source ID, and attachment ID; policy version, document hash, and observation time belong to the snapshot.
- Evaluates frozen policy documents with a conservative rule set, stores append-only policy risk and separate grant-path assessments, and escalates unsupported evidence and partial action wildcards to HIGH. Known Identity Center statements remain visible even when another referenced document is missing. These assessments do not establish a principal's effective permissions.
- Creates campaigns only against a fresh complete published snapshot with assessments for every observed path. A duplicate active campaign for the same snapshot is blocked, and grant conflicts roll back the entire creation. Each review is pinned to its snapshot, grant observation, and risk assessment. Older records are labelled `legacy_unknown_path`.
- When multiple accounts have published snapshots, campaign generation requires an explicit `account_id` in its event so one account's evidence cannot be selected implicitly.
- Offers a mock-only reviewer CLI and an OIDC-protected API with campaign owners, deadlines, states, reviewer queues, per-review assignments, exceptions, and immutable workflow events. A closed campaign cannot reopen; open exceptions and paused campaigns block decisions.
- Keeps remediation in dry-run mode by default. Staging live execution requires `APP_ENV=staging`, `AWS_ACCOUNT_ID`, `STAGING_REMEDIATION_ACCEPTANCE_ID`, `ENABLE_REMEDIATION=true`, `ALLOW_LIVE_REMEDIATION=true`, `DRY_RUN=false`, and a non-empty exact-match allowlist. Production live execution remains blocked. The worker supports direct managed and direct inline IAM user policy paths; group, role, trust, and Identity Center paths remain ineligible.
- Exports unique CSV/JSON artifacts and a manifest with SHA-256 hashes. S3 uploads use a per-export run path and surface upload errors.
- Persists audit events, decision-bound artifact IDs, durable AI jobs and attempts, and immutable validated AI artifacts. Legacy summaries remain a labelled compatibility view.

## GenAI explanation

GenAI is advisory and disabled by default. For eligible pending HIGH-risk, snapshot-pinned reviews, the worker creates an idempotent database job, sends minimized frozen rule evidence with an HMAC-pseudonymized subject to the configured provider, validates typed output and exact evidence IDs, and stores an immutable artifact. A lease and retry budget prevent duplicate workers from publishing competing artifacts. Provider or validation failures retry and then produce a labelled deterministic fallback. The worker does not write decisions, approvals, or remediation state.

The assigned reviewer's `GET /reviews/{review_id}` response, audit exports, and CLI all use the same artifact projection. `authority=validated_artifact` identifies validated output and resolves citations against the review's pinned evidence. Old `ai_risk_summary` records remain readable only as `authority=legacy_compatibility`; the worker no longer writes that column. A decision event records the artifact ID visible at decision time. Missing output is explicit. Jobs pin the provider model; a model change creates a new generation, and campaign admins can queue an audited retry of a `FAILED` job with `POST /ai/jobs/{job_id}/retry`.

Enable it only after reviewing provider and data-handling requirements:

```bash
export ENABLE_GENAI=true
export GOOGLE_API_KEY=your_key_here
export AI_PROVIDER_DATA_APPROVED=true
export AI_PSEUDONYM_KEY=your_secret_from_a_secret_manager
export GENAI_MODEL=gemini-3.8-flash
```

The worker sends redacted risk evidence and a policy hash, not the full policy document. Resource strings can still contain sensitive context, so provider/data approval and a secret pseudonym key are required. Review [AI quality gates](docs/ai-quality-gates.md) before enabling broader brief, Q&A, or campaign insight tasks.

## Local mock quickstart

```bash
python -m venv .venv
# Activate the environment for your shell, then:
pip install -r requirements.txt
export DB_URL=sqlite:///iam_governance.db
export MOCK_IAM=true
export LOCAL_ONLY=true
python scripts/migrate.py
python lambdas/identity_discovery/handler.py
python lambdas/role_discovery/handler.py  # separate mock role source
python lambdas/risk_evaluation/handler.py
python lambdas/generate_reviews/handler.py
python lambdas/ai_explanation/handler.py  # skips provider if disabled
python scripts/review.py list --status PENDING
```

The demo script runs these stages and a simulated reviewer cycle. It preserves the configured database; select a fresh `DB_URL` when you want a clean demo database.

## Reviewer CLI

```bash
python scripts/review.py list --status PENDING --risk HIGH
python scripts/review.py decide --review-id <id> --decision REVOKED --comment "Least privilege review"
python scripts/review.py stats
python scripts/review.py audit --tail 20
```

`auto-demo` creates simulated decisions and requires `MOCK_IAM=true` plus a pinned `MOCK` snapshot. CLI decisions are restricted to the same evidence source; legacy/unpinned and AWS-sourced reviews are rejected even if the runtime mock flag is set. Only OIDC API decision events satisfy the non-production live-remediation approval gate. Use the OIDC review API for real review decisions after configuring issuer, audience, JWKS, reviewer group, and campaign administrator group.

Run the API behind a TLS-terminating gateway with restricted network access:

```bash
uvicorn api.review_service:app --host 127.0.0.1 --port 8080
```

Campaign administrators assign reviewers with `POST /campaigns/{campaign_id}/reviewers`, assign individual reviews with `POST /reviews/{review_id}/assignment`, and manage campaign state, owner, deadlines, and exceptions through the API. Assigned reviewers use `GET /reviews/queue?limit=100&offset=0` for paged queues; campaign events also accept `limit` and `offset`. The API exposes frozen path and policy evidence, source coverage and freshness, and reports principal access as `not_evaluated`. A different authenticated remediation approver must approve a revoked, snapshot-pinned direct user policy path before staging live execution. Approval and action events bind the exact decision, snapshot, grant, and worker outcome. `GET /reviews/{review_id}/remediation` exposes that history to authorized reviewers, admins, approvers, and remediation operators. When an action outcome requires reconciliation, an operator in `REMEDIATION_OPERATOR_GROUP` can submit `POST /reviews/{review_id}/remediation/reconciliation` with a nonblank `reason`; the staging worker then performs a read-only exact-path AWS check and records an immutable result. A still-present or unreadable path remains on hold, and the worker does not repeat the destructive action. A newer scan requires a new pinned review and approval; a failed newer scan blocks live action while retaining the prior snapshot for audit. See [staging remediation acceptance](docs/staging-remediation-acceptance.md) before setting the staging gate.

## Configuration

- `DB_URL`: SQLite path or Postgres URL.
- `AWS_REGION`, `AWS_PROFILE`, `AWS_ACCOUNT_ID`: AWS discovery settings. `AWS_ACCOUNT_ID` is required for real IAM user and role scans so a failed STS check is recorded against the intended source. User/group scans need IAM policy and group read permissions; role scans additionally need `iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, and `iam:GetRolePolicy`. Identity Center scans need account assignment and permission set read permissions plus identity-store describe permissions. Live direct-path preflight also reads the current user identity.
- `MOCK_IAM`: use the seeded data instead of AWS.
- `ENABLE_GENAI`, `GOOGLE_API_KEY`, `GENAI_MODEL`, `AI_PROVIDER_DATA_APPROVED`, `AI_PSEUDONYM_KEY`: advisory explanation worker and privacy gates.
- `DRY_RUN`, `ENABLE_REMEDIATION`, `ALLOW_LIVE_REMEDIATION`, `REMEDIATION_ALLOWLIST`, `REMEDIATION_DENYLIST`, `STAGING_REMEDIATION_ACCEPTANCE_ID`, `REMEDIATION_WORKER_ID`: remediation gates and audit actor. Mandatory administrator and break-glass deny patterns cannot be removed by configuration.
- `AUDIT_S3_BUCKET`, `AUDIT_S3_PREFIX`, `LOCAL_ONLY`: audit export target.
- `APP_ENV`: environment mode; only `staging` can execute live remediation after the other gates pass. Production remains code-blocked. The review API always requires valid OIDC configuration.
- `MAX_DISCOVERY_AGE_HOURS`: maximum age of a complete AWS scan for non-production live remediation (default 24, maximum 168).
- `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, `OIDC_GROUP_CLAIM`, `REVIEWER_GROUP`, `CAMPAIGN_ADMIN_GROUP`, `REMEDIATION_APPROVER_GROUP`, `REMEDIATION_OPERATOR_GROUP`: OIDC and authorization configuration for the review API.

Copy `.env.example` for local configuration. Do not commit credentials.

## Schema and audit outputs

Ordered migrations are in `sql/migrations/`. Each numbered portable SQL file may have a matching `.sqlite.sql` or `.postgres.sql` file. Run `python scripts/migrate.py` before starting workers or the review API. The runner applies pending migrations transactionally, records a SHA-256 checksum in `schema_migrations`, and rejects edited or missing applied migrations. Migration 0001 also upgrades older databases that predate its compatibility columns. Add new numbered files for future schema changes; do not edit an applied migration. Export artifacts are written under `reports/` using date plus unique run ID, with a `.manifest.json` file. Set `LOCAL_ONLY=true` to skip S3.

GitHub Actions runs the SQLite suite and a separate Postgres 17 service job for fresh and upgrade migrations, source publication, concurrent remediation claims, and AI job claims in [.github/workflows/ci.yml](.github/workflows/ci.yml). AWS, Identity Center, S3, and AI provider integrations are not part of these CI jobs.

## Known boundaries

- A revoked path is a decision about that path; other grants can still give the principal similar access. The system does not compute aggregate effective access. Descriptive user/policy tables can retain stale entities even though the published grant view is source-scoped.
- Historical reviews created before snapshot pinning retain unknown path and policy-version provenance; the current mutable policy must not be treated as their historical evidence.
- The reviewer CLI is not an authentication system.
- Deployment infrastructure, event sources, secret-manager integration, provider retention approval, and production alerting are not defined here.
- Local tests and the Postgres service test do not establish AWS, S3, AI-provider, or production deployment readiness.
