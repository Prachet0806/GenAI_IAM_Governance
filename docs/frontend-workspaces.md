# IAM governance frontend workspaces

## Local container deployment

Copy `.env.example` to `.env`, set a strong `POSTGRES_PASSWORD`, and provide the organization's OIDC issuer, client credentials, audience, and JWKS URL. Set `AUTH_SECRET` to a fresh random value. Register the frontend callback at `/api/auth/callback/corporate-oidc` with the identity provider. The compose profile keeps IAM discovery in mock mode, GenAI disabled, and remediation in dry-run mode.

Start the stack with `docker compose up --build`. The frontend listens on `127.0.0.1:3000`; place it behind a TLS-terminating proxy for shared use. Database migrations run once before the API starts. The PostgreSQL volume and generated report files persist locally. Stop with `docker compose down`; `docker compose down -v` removes the local database volume.

## Role workspaces

- Reviewer: assigned queue, evidence detail, decision and history.
- Campaign administrator: published snapshot readiness, campaign creation, reviewer pool and assignments, progress, exceptions and lifecycle events.
- Remediation approver: independent approval queue, eligibility blockers, decision reason, execution/reconciliation history.
- Auditor: scoped decision history, export generation, download and manifest verification.
- Platform operator: health, configured integrations, recorded processing activity, redacted operational events and exact-path reconciliation requests.

The backend authorizes each request and account scope. The browser receives only the `/me` role summary; bearer access tokens stay in the server-side Auth.js session and BFF. Campaign and export aggregates are calculated only after scope predicates are applied. Operations activity does not imply worker liveness: this release reports worker heartbeat as unavailable until a heartbeat source is deployed.

## Deployment boundary

The compose configuration is a local integration deployment. It is not an AWS staging deployment: it does not provision a public domain, managed identity provider, WAF, managed database, worker fleet, KMS key, or AWS IAM permissions. Keep live remediation, production IAM discovery, provider data sharing, and production secrets disabled until those controls are configured and the staging acceptance runbook is completed.
