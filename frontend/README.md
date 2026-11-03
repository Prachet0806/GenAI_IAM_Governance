# IAM Governance frontend

The Next.js app provides separate workspaces for the governance roles. It uses the existing unversioned FastAPI routes through a same-origin backend-for-frontend (BFF). The API and IAM evidence engine remain authoritative for access control and decisions.

## Workspaces

- **Reviewer:** assigned review queue, filters, frozen grant/policy/risk evidence, decision, AI explanation status, and history.
- **Campaign administrator:** published snapshot readiness, campaign creation, reviewer pool and per-review assignment, progress, lifecycle events, deadlines, and exception resolution. Campaign administrators can read scoped review evidence; this does not grant decision permission.
- **Remediation approver:** revoked-review queue, independent eligibility blockers, approve/decline reason, and execution/reconciliation history.
- **Auditor:** scoped decision/workflow history, export creation and download, and manifest/artifact verification.
- **Platform operator:** service and dependency configuration, recorded processing activity, redacted operational events, and exact-path reconciliation requests. Worker heartbeat is currently unavailable and is shown as such.

The frontend presents decisions about an observed grant path. It does not infer that a principal has lost equivalent or effective access through other paths. GenAI explanations remain advisory.

After sign-in, `/` reads the authenticated `/me` role summary and routes to the first available workspace in this order: reviewer, campaign administrator, remediation approver, auditor, then platform operator. Users with no configured workspace role receive an access-denied page. This routing is navigation only; API authorization remains authoritative.

## Local development

1. Install Node.js 22 and pnpm 11.25.0.
2. Install the repository's Python requirements and apply database migrations with `python scripts/migrate.py`.
3. Start the FastAPI service, for example with `uvicorn api.review_service:app --host 127.0.0.1 --port 8080`.
4. Copy `frontend/.env.example` to `frontend/.env.local`. Set `AUTH_OIDC_ISSUER`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, `AUTH_SECRET`, and `IAM_API_BASE_URL`. Keep secrets in a local secret store.
5. Register `http://localhost:3000/api/auth/callback/corporate-oidc` as an OIDC redirect URI.
6. From this directory, run `pnpm install`, `pnpm api:types`, and `pnpm dev`.

The API must accept the access-token audience it validates. Configure API `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, `OIDC_GROUP_CLAIM`, and role-group values to match the identity provider. `OIDC_ACCOUNT_SCOPE_CLAIM` should identify the authorized AWS account IDs; if account scope is omitted, API behavior follows its configured global-scope rules. The API uses OIDC `sub` for actor identity and authorization.

## Local container stack

For a containerized integration setup, configure the repository-root `.env` from `.env.example` and run `docker compose up --build` from the repository root. Compose runs PostgreSQL migrations before the API and binds the frontend to `127.0.0.1:3000`. It defaults to mock IAM, disabled GenAI, and dry-run remediation. Use the root [deployment guide](../docs/frontend-workspaces.md) for details.

This stack is not an AWS staging deployment. It does not provision an identity provider, public endpoint/TLS, WAF, managed database, AWS IAM roles, worker fleet, KMS, or cloud monitoring.

## API contract and security

`src/lib/api/schema.d.ts` is generated from `openapi.json`; update it with `pnpm api:types` after API changes. `src/app/api/backend/[...path]/route.ts` keeps the access token server-side, enforces a route/method allowlist and origin check for writes, and forwards only to `IAM_API_BASE_URL`. The API still performs role, resource, and account-scope authorization before returning data or aggregates. Do not treat hidden navigation or disabled buttons as authorization.

## Checks

```bash
pnpm typecheck
pnpm lint
pnpm test
pnpm build
```

The root CI workflow also builds the API and frontend container images. Local checks do not establish hosted CI, AWS, S3, provider, or production deployment status.
