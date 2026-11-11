# IAM governance frontend workspaces

## Local container deployment

Copy `.env.example` to `.env`, set a strong `POSTGRES_PASSWORD`, and provide the organization's OIDC issuer, client credentials, audience, and JWKS URL. Set `AUTH_SECRET` to a fresh random value. Register the frontend callback at `/api/auth/callback/corporate-oidc` with the identity provider. The compose profile keeps IAM discovery in mock mode, GenAI disabled, and remediation in dry-run mode.

Start the stack with `docker compose up --build`. The frontend listens on `127.0.0.1:3000`; place it behind a TLS-terminating proxy for shared use. Database migrations run once before the API starts. The PostgreSQL volume and generated report files persist locally. Stop with `docker compose down`; `docker compose down -v` removes the local database volume.

## Role workspaces

- Reviewer: campaign-pool queue, evidence detail, decision and history. Explicitly assigned reviews are limited to that reviewer; unassigned reviews are available to any reviewer in the campaign pool.
- Campaign administrator: published snapshot readiness, campaign creation, reviewer pool and assignments, progress, exceptions and lifecycle events.
- Remediation approver: independent approval queue, eligibility blockers, decision reason, execution/reconciliation history.
- Auditor: scoped decision history, export generation, download and manifest verification.
- Platform operator: health, configured integrations, recorded processing activity, redacted operational events and exact-path reconciliation requests.

The backend authorizes each request and account scope. The browser receives only the `/me` role summary; bearer access tokens stay in the server-side Auth.js session and BFF. Campaign and export aggregates are calculated only after scope predicates are applied. Compose forwards `OIDC_ACCOUNT_SCOPE_CLAIM`, defaulting to `aws_account_scopes`; missing, empty, or malformed claim values receive no account-scoped access. Staging and production refuse API startup if the claim name is not configured. An explicit wildcard in the trusted identity-provider claim grants global scope; local global scope otherwise requires `OIDC_ALLOW_GLOBAL_SCOPE=true`. Operations activity does not imply worker liveness: this release reports worker heartbeat as unavailable until a heartbeat source is deployed.

Campaign reviewer assignment has no identity-provider directory integration. Shared environments reject assignment and reassignment until provider-backed eligibility lookup is available. Local development can explicitly enable unverified subject entry with `OIDC_ALLOW_UNVERIFIED_REVIEWER_ASSIGNMENTS=true`; do not use that setting for authenticated staging acceptance.

## Frontend interaction and verification

The workspaces render named governance fields and workflow states rather than arbitrary response keys. Paginated lists request bounded server-side pages; the reviewer queue can filter status, risk, and search text and sort by due date, risk, or principal. Campaign administrators can allocate or reassign selected pending reviews, with separate API requests and a clear partial-success message. Audit event type is an exact match filter. Confirmation dialogs identify the principal, account, grant path, snapshot, or target before high-impact actions.

Run `pnpm test:e2e` from `frontend` for browser journeys across the five roles. These tests mint a test-only Auth.js session, mock `/api/backend` responses, and run Axe against WCAG 2.2 AA criteria on each workspace. Automated checks do not replace manual assistive-technology testing. The journeys do not establish real OIDC, API authorization, AWS connectivity, worker execution, or cloud deployment readiness. Notifications, global search, and identity-provider reviewer lookup need supporting API endpoints before they can be represented as live product capabilities. Effective access across every possible grant path remains unevaluated by the engine.

## Deployment boundary

The compose configuration is a local integration deployment. It is not an AWS staging deployment: it does not provision a public domain, managed identity provider, WAF, managed database, worker fleet, KMS key, or AWS IAM permissions. Keep live remediation, production IAM discovery, provider data sharing, and production secrets disabled until those controls are configured and the staging acceptance runbook is completed.
