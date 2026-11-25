# Frontend setup and workspaces

The Next.js app uses unversioned FastAPI routes through a same-origin BFF. Auth.js holds access tokens server-side; the API decides role, AWS account scope, resource access, and decision eligibility. The UI covers five roles:

| Workspace | Main work |
| --- | --- |
| Reviewer | Filterable assigned queue, frozen grant/statement/risk evidence, decision, AI explanation/Q&A when enabled, and history. |
| Campaign admin | Snapshot readiness/comparison, campaign creation and lifecycle, reviewer pool and per-review assignment, deadlines and exceptions. Scoped evidence read does not grant decision permission. |
| Remediation approver | Independent approve/decline with eligibility blockers and action/reconciliation history. |
| Auditor | Scoped history and verifiable CSV/JSON/evidence/manifest exports. |
| Operator | Health, integration configuration, recorded jobs/redacted events, and read-only exact-path reconciliation. Worker heartbeat is unavailable. |

The landing page routes to the first available role in that order; users with none see access denied. Lists use bounded API `limit`/`offset` pages. Confirmation dialogs show impact; bulk assignment makes separate requests and can partially succeed. A review decision concerns **one observed grant path**, not all effective access.

## Local development

1. Install Node.js 22 and pnpm 11.25.0. Install root Python requirements and run `python scripts/migrate.py`.
2. Start `uvicorn api.review_service:app --host 127.0.0.1 --port 8080` from the root.
3. Copy `frontend/.env.example` to `frontend/.env.local`. Set `AUTH_OIDC_ISSUER`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, `AUTH_SECRET`, and `IAM_API_BASE_URL`. Register `http://localhost:3000/api/auth/callback/corporate-oidc` with the identity provider.
4. Configure API `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, role-group names, and `OIDC_ACCOUNT_SCOPE_CLAIM` to match the provider. Staging/production deny account access if the scope claim is missing or invalid. Shared-environment reviewer assignment needs directory-backed membership verification; unverified subject entry is a local opt-in only.
5. From `frontend`, run `pnpm install`, `pnpm api:types`, and `pnpm dev`.

For the local container stack, fill root `.env` from `.env.example`, including `POSTGRES_PASSWORD`, OIDC credentials, and a fresh `AUTH_SECRET`; run `docker compose up --build` from the root. Migrations run before API startup. PostgreSQL data and reports persist locally; `docker compose down -v` deletes the local database volume. Compose uses Floci (`MOCK_IAM=false`), disabled GenAI, and dry-run remediation. Frontend and emulator bind host loopback; use a TLS proxy for shared access. This is not managed AWS/OIDC staging.

`frontend/src/lib/api/schema.d.ts` comes from `frontend/openapi.json`; regenerate with `pnpm api:types` after API changes. The BFF route/method allowlist and write-origin check are in `frontend/src/app/api/backend/[...path]/route.ts`. See the [API permission contract](../docs/frontend-api-contract.md) and [deployment gate](../docs/production-readiness.md).

## Checks

Run `pnpm typecheck`, `pnpm lint`, `pnpm test`, `pnpm build`, and `pnpm test:e2e`. Install the Playwright Chromium binary with `pnpm exec playwright install chromium` if needed. E2E runs five role journeys with test-only Auth.js sessions, mocked BFF responses, and Axe checks against WCAG 2.2 AA. These checks do not establish real OIDC, backend authorization, AWS behavior, worker execution, or manual assistive-technology acceptance. Keep test secrets out of deployment.
