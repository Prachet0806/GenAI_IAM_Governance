# IAM Access Certification Engine

A Python prototype for IAM inventory, entitlement risk assessment, access review campaigns, gated remediation, and audit exports. It supports local SQLite/Postgres and a seeded mock IAM dataset. It is not production-ready; see [production readiness](docs/production-readiness.md) for limitations and required controls.

## Current capabilities

- Discovers IAM users, their direct managed and inline policies, and the managed/inline policies inherited through IAM groups. Managed policy default versions are recorded. It does not yet discover IAM roles, Identity Center, permission boundaries, SCPs, or resource policies.
- Records discovery runs. Only a complete scan replaces current user-policy links; failed/incomplete scans retain the previous links.
- Evaluates discovered policy documents with a conservative rule set, records evidence and rule version, and escalates missing/invalid or unsupported evidence to HIGH for manual review. This is not a full AWS effective-permissions evaluator.
- Creates review campaigns with race-safe pending-review insertion.
- Offers a local prototype reviewer CLI restricted to mock data for decisions, plus an OIDC-protected review API with campaign assignments.
- Keeps remediation in dry-run mode by default. Live detachment additionally requires `ENABLE_REMEDIATION=true`, `ALLOW_LIVE_REMEDIATION=true`, `DRY_RUN=false`, and a non-empty exact-match allowlist. The current worker only detaches direct managed user policies; group-derived and inline policies are skipped.
- Exports unique CSV/JSON artifacts and a manifest with SHA-256 hashes. S3 uploads use a per-export run path and surface upload errors.
- Persists audit events for key stages and stores AI generations with explicit provenance.

## GenAI explanation

GenAI is advisory and disabled by default. For eligible pending HIGH-risk reviews, the handler loads trusted database context, pseudonymizes the user identifier, sends policy/risk evidence to the configured provider, validates structured output, and records an append-only generation. It does not approve, revoke, or execute access changes. A deterministic fallback is recorded with `source=FALLBACK` when a provider call fails.

Enable it only after reviewing provider and data-handling requirements:

```bash
export ENABLE_GENAI=true
export GOOGLE_API_KEY=your_key_here
export GENAI_MODEL=gemini-3.8-flash
```

The policy documents remain sensitive information even though direct user identifiers are removed. See the production-readiness guide before sending real identity data to a provider.

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

`auto-demo` creates simulated decisions and is restricted to `MOCK_IAM=true`. CLI decisions are restricted to mock data. Use the OIDC review API for real review decisions after configuring issuer, audience, JWKS, reviewer group, and campaign administrator group.

Run the API behind a TLS-terminating gateway with restricted network access:

```bash
uvicorn api.review_service:app --host 127.0.0.1 --port 8080
```

Campaign administrators assign reviewers using `POST /campaigns/{campaign_id}/reviewers`; assigned reviewers can read and decide reviews in that campaign. A different authenticated principal in the remediation approver group must approve a revoked review through `POST /reviews/{review_id}/remediation-approval` before any non-production live detach. The approval is bound to the latest complete discovery run and must be renewed after a new snapshot. The API validates signed OIDC access tokens and requires exact group membership. Configure token claims and TLS at the identity provider and gateway.

## Configuration

- `DB_URL`: SQLite path or Postgres URL.
- `AWS_REGION`, `AWS_PROFILE`: AWS account discovery settings. IAM discovery also needs group membership, group policy, and inline policy read permissions (`iam:ListGroupsForUser`, `iam:ListAttachedGroupPolicies`, `iam:ListGroupPolicies`, `iam:GetGroupPolicy`, `iam:ListUserPolicies`, `iam:GetUserPolicy`).
- `MOCK_IAM`: use the seeded data instead of AWS.
- `ENABLE_GENAI`, `GOOGLE_API_KEY`, `GENAI_MODEL`: optional explanation provider controls.
- `DRY_RUN`, `ENABLE_REMEDIATION`, `ALLOW_LIVE_REMEDIATION`, `REMEDIATION_ALLOWLIST`, `REMEDIATION_DENYLIST`: remediation gates. Mandatory administrator and break-glass deny patterns cannot be removed by configuration.
- `AUDIT_S3_BUCKET`, `AUDIT_S3_PREFIX`, `LOCAL_ONLY`: audit export target.
- `APP_ENV`: environment mode; production live remediation is intentionally blocked in code pending deployment and staging acceptance. The review API always requires valid OIDC configuration.
- `MAX_DISCOVERY_AGE_HOURS`: maximum age of a complete AWS scan for non-production live remediation (default 24, maximum 168).
- `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, `OIDC_GROUP_CLAIM`, `REVIEWER_GROUP`, `CAMPAIGN_ADMIN_GROUP`, `REMEDIATION_APPROVER_GROUP`: OIDC and authorization configuration for the review API.

Copy `.env.example` for local configuration. Do not commit credentials.

## Schema and audit outputs

Ordered migrations are in `sql/migrations/`. Each numbered portable SQL file may have a matching `.sqlite.sql` or `.postgres.sql` file. Run `python scripts/migrate.py` before starting workers or the review API. The runner applies pending migrations transactionally, records a SHA-256 checksum in `schema_migrations`, and rejects edited or missing applied migrations. Migration 0001 also upgrades older databases that predate its compatibility columns. Add new numbered files for future schema changes; do not edit an applied migration. Export artifacts are written under `reports/` using date plus unique run ID, with a `.manifest.json` file. Set `LOCAL_ONLY=true` to skip S3.

GitHub Actions runs the SQLite suite and a separate Postgres 17 service job for fresh and legacy migrations and concurrent remediation claims in [.github/workflows/ci.yml](.github/workflows/ci.yml). AWS, S3, and AI provider integrations are not part of these CI jobs.

## Known boundaries

- Name heuristics remain as a fallback signal when policy evidence is unavailable; incomplete IAM surface coverage prevents full effective-access conclusions. Group membership changes and policy reads are currently reconciled only for discovered users; stale user/group/policy entities may remain in the descriptive tables after a complete scan.
- The reviewer CLI is not an authentication system.
- Deployment infrastructure, event sources, secret-manager integration, provider retention approval, and production alerting are not defined here.
- Local execution does not establish AWS, Postgres, S3, or provider readiness.
