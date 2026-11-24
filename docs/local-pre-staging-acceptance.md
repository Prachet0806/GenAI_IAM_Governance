# Local pre-staging acceptance record

Run date: 2026-11-03

## Local results

- `& '.\.venv\Scripts\python.exe' -m pytest -q`: **86 passed, 9 skipped**. The run reports one existing Starlette/httpx deprecation warning.
- Frontend TypeScript check: **passed**.
- Frontend ESLint: **passed**.
- Frontend Vitest: **8 passed**.
- Frontend production build: **passed**.
- Playwright workspaces: **5 passed**, including the five-role journeys and automated accessibility scans.
- `git diff --check`: **passed**.

The Python suite now exercises OIDC issuer, audience, signing-key/signature, expiration, and required-claim rejection; account-scope startup and claim validation; one-account, multi-account, empty, malformed, and wildcard scopes; cross-campaign isolation; reviewer-pool and individual-review eligibility; and the existing evidence freshness, remediation, and audit regressions.

The browser journeys use a test-only Auth.js session and mocked BFF responses. They validate frontend behavior and do not establish real OIDC authentication, backend authorization, AWS connectivity, or deployment readiness.

## Not run: production-like Compose authentication

The local environment does not have `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, `AUTH_OIDC_ISSUER`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, or `AUTH_SECRET` configured. The authenticated Compose flow was therefore not started. No live identity-provider, multi-account, or AWS staging result is claimed.

Reviewer campaign assignment and reassignment also remain unavailable in staging/production until a provider-backed directory lookup is implemented. The API returns a service-unavailable response rather than accepting an unverified subject. The identity provider and its directory API were not specified, so no provider integration is claimed.

## Readiness

The local authorization fixes and regression checks pass. Multi-account authenticated testing remains gated on (1) wiring real OIDC test configuration and running the Compose flow, and (2) implementing and testing reviewer lookup and membership revalidation against the selected identity provider.
