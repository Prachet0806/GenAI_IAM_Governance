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
- Includes a role-scoped Next.js frontend for reviewers, campaign administrators, independent remediation approvers, auditors, and platform operators. Server-side APIs enforce role and AWS account scope; the frontend does not replace the discovery, evidence, risk, or remediation safety model.

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

The role workspaces use the existing unversioned API. Campaign administrators can check `GET /snapshots/{snapshot_id}/readiness`, create a campaign with `POST /campaigns`, assign reviewers, allocate individual reviews, and monitor progress and lifecycle events. Reviewers use a filterable, offset-paginated `GET /reviews/queue` and can inspect frozen grant evidence and decision history. Campaign administrators can also open scoped, read-only review evidence; decision mutations still require reviewer authorization and assignment. Remediation approvers use `GET /approvals` and `/approvals/{review_id}`, then record an independent approval or decline with a reason at `/approvals/{review_id}/decision`. Auditors use `GET /audit/events` and the scoped `/exports` endpoints to create, download, and verify manifests. Operators use `/operations/health`, `/operations/integrations`, `/operations/jobs`, and `/operations/audit`; worker heartbeat is reported as unavailable until an actual heartbeat source is deployed. The generated frontend API schema is in `frontend/src/lib/api/schema.d.ts`; the proposed `/api/v1` routes in the contract document are not the routes currently called by the app.

### Frontend workspaces

The local frontend and container setup are described in [frontend workspaces](docs/frontend-workspaces.md) and [frontend setup](frontend/README.md). For a local OIDC-backed integration stack, copy `.env.example` to `.env`, configure the API and frontend OIDC settings and group names, then run:

```bash
docker compose up --build
```

The stack uses PostgreSQL, runs migrations before starting the API, and defaults to mock IAM discovery, disabled GenAI, and dry-run remediation. The frontend is bound to `127.0.0.1:3000`. This is a local integration deployment, not AWS staging or production infrastructure. For frontend development without containers, follow `frontend/README.md`.

## Configuration

- `DB_URL`: SQLite path or Postgres URL.
- `AWS_REGION`, `AWS_PROFILE`, `AWS_ACCOUNT_ID`: AWS discovery settings. `AWS_ACCOUNT_ID` is required for real IAM user and role scans so a failed STS check is recorded against the intended source. User/group scans need IAM policy and group read permissions; role scans additionally need `iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, and `iam:GetRolePolicy`. Identity Center scans need account assignment and permission set read permissions plus identity-store describe permissions. Live direct-path preflight also reads the current user identity.
- `MOCK_IAM`: use the seeded data instead of AWS.
- `ENABLE_GENAI`, `GOOGLE_API_KEY`, `GENAI_MODEL`, `AI_PROVIDER_DATA_APPROVED`, `AI_PSEUDONYM_KEY`: advisory explanation worker and privacy gates.
- `DRY_RUN`, `ENABLE_REMEDIATION`, `ALLOW_LIVE_REMEDIATION`, `REMEDIATION_ALLOWLIST`, `REMEDIATION_DENYLIST`, `STAGING_REMEDIATION_ACCEPTANCE_ID`, `REMEDIATION_WORKER_ID`: remediation gates and audit actor. Mandatory administrator and break-glass deny patterns cannot be removed by configuration.
- `AUDIT_S3_BUCKET`, `AUDIT_S3_PREFIX`, `LOCAL_ONLY`: audit export target.
- `APP_ENV`: environment mode; only `staging` can execute live remediation after the other gates pass. Production remains code-blocked. The review API always requires valid OIDC configuration.
- `MAX_DISCOVERY_AGE_HOURS`: maximum age of a complete AWS scan for non-production live remediation (default 24, maximum 168).
- `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, `OIDC_GROUP_CLAIM`, `OIDC_ACCOUNT_SCOPE_CLAIM`, `REVIEWER_GROUP`, `CAMPAIGN_ADMIN_GROUP`, `REMEDIATION_APPROVER_GROUP`, `REMEDIATION_OPERATOR_GROUP`, `AUDITOR_GROUP`: OIDC and authorization configuration for the API. Use immutable OIDC `sub` values for actors and reviewer assignments; the account-scope claim is enforced by the API.
- Frontend `AUTH_OIDC_ISSUER`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, `AUTH_SECRET`, `AUTH_SCOPE`, `IAM_API_BASE_URL`, and `FRONTEND_ORIGIN`: Auth.js OIDC client, server-side API proxy, and CSRF origin configuration. Keep client secrets and signing secrets outside source control.
- Local Compose `POSTGRES_PASSWORD` and optional `FRONTEND_PORT`: local database credential and loopback frontend port.

Copy `.env.example` for local configuration. Do not commit credentials.

## Schema and audit outputs

Ordered migrations are in `sql/migrations/`. Each numbered portable SQL file may have a matching `.sqlite.sql` or `.postgres.sql` file. Run `python scripts/migrate.py` before starting workers or the review API. The runner applies pending migrations transactionally, records a SHA-256 checksum in `schema_migrations`, and rejects edited or missing applied migrations. Migration 0001 also upgrades older databases that predate its compatibility columns. Add new numbered files for future schema changes; do not edit an applied migration. Export artifacts are written under `reports/` using date plus unique run ID, with a `.manifest.json` file. Set `LOCAL_ONLY=true` to skip S3.

GitHub Actions is configured to run the SQLite suite, a separate Postgres 17 migration/concurrency job, frontend typecheck/lint/unit tests/build, and API/frontend container image builds in [.github/workflows/ci.yml](.github/workflows/ci.yml). A workflow definition is not evidence that hosted CI passed at this checkout. AWS, Identity Center, S3, OIDC-provider integration, and AI-provider calls are not exercised by these jobs.

## Known boundaries

- A revoked path is a decision about that path; other grants can still give the principal similar access. The system does not compute aggregate effective access. Descriptive user/policy tables can retain stale entities even though the published grant view is source-scoped.
- Historical reviews created before snapshot pinning retain unknown path and policy-version provenance; the current mutable policy must not be treated as their historical evidence.
- The reviewer CLI is not an authentication system.
- Docker Compose supports a local integration stack only. Cloud infrastructure, managed identity, TLS/WAF, worker scheduling and heartbeat, secret-manager integration, provider retention approval, and production alerting are not provisioned here.
- Local tests and the Postgres service test do not establish AWS, S3, AI-provider, or production deployment readiness.
