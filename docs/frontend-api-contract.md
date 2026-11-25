# Frontend and API contract

The Next.js frontend calls **unversioned** FastAPI routes through a same-origin BFF. `frontend/openapi.json` and `frontend/src/lib/api/schema.d.ts` are generated from the current API. `/api/v1`, cursor pagination, generic idempotency keys, and metadata `If-Match` are proposals, not routes used by this app. The API is authoritative for role, resource, account scope, and decision eligibility; hidden UI controls are navigation only.

## Current route and workspace map

| Workspace | Current endpoints and behavior | Access |
| --- | --- | --- |
| Reviewer | `GET /reviews/queue`, `/reviews/summary`, `/reviews/{id}`, `/reviews/{id}/history`; `POST /reviews/{id}/decision`. Detail includes pinned path/policy/assessment, uncertainty, current eligibility, `principal_access_status=not_evaluated`, AI artifact/provenance, and API-computed `can_decide`. Queue uses bounded `limit`/`offset`, filters and sort. | OIDC reviewer group, account scope, campaign reviewer pool; explicit assignment narrows a review to its assignee. OPEN campaign, pending review, and no open exception for a decision. `REVOKED` needs a comment; duplicate/racing decisions conflict. |
| Campaign administrator | `GET /campaigns`, `/campaigns/{id}` plus progress/reviews/reviewers/events; `GET /snapshots`, `/snapshots/{id}/readiness`, `/discovery-attempts`, `/sources/{account}/coverage`, `/snapshots/{id}/compare/{other}`; `POST /campaigns`, reviewer pool/assignment, state, owner, deadline, exception resolution, and snapshot invalidation. Comparison is same-account/scope observed paths, with windows and hashes. | Admin group and account scope. Creation rechecks current published evidence/risk; assignment in shared environments fails closed without directory verification. Admin evidence read does not grant decision permission. |
| Remediation approver | `GET /approvals`, `/approvals/{review_id}`, `/reviews/{id}/remediation`; `POST /approvals/{review_id}/decision` (approve/decline with reason). Older `/reviews/{id}/remediation-approval` is an approval-only compatibility route. | Approver group, account scope, independent `sub` from reviewer. Approval does not prove AWS mutation. |
| Auditor | `GET /audit/events`, `/audit/reviews/{id}`; `/exports` list/create/detail/verify/download (CSV, JSON, evidence bundle, manifest). Historical pins and current eligibility are labelled separately. | Auditor or scoped campaign admin; authorize **before** counts, aggregates, artifact access, or download. |
| Operator | `GET /operations/health`, `/integrations`, `/jobs`, `/audit`; `POST /reviews/{id}/remediation/reconciliation`. Integrations reports current provider-approval status separately from its flag. | Operator group; resource-bound records remain account-scoped. Recorded jobs do not establish worker heartbeat or integration connectivity. Reconciliation is read-only, scoped, and needs a reason. |
| AI | `POST /reviews/{id}/ai/explanation`, `GET /ai/jobs/{id}`, `POST /ai/jobs/{id}/retry`, `POST /reviews/{id}/ai/questions`. Q&A accepts four bounded intents and returns validated pinned claims or abstention. | Explanation needs current provider approval and assigned review; retry needs admin authority. Q&A is default-off and reauthorizes current reviewer/account/assignment on every turn. See [AI governance](ai-governance.md). |

The frontend routes users after sign-in by available role (reviewer, campaign admin, approver, auditor, operator). Users without a role see access denied. Its BFF keeps bearer tokens in the server-side Auth.js session, enforces route/method allowlists and write-origin checks, and forwards to `IAM_API_BASE_URL`. The API checks the OIDC signature, issuer, audience, expiry, `sub`, group, account scope, and object binding. Missing/empty/malformed scope grants no account access; an explicit trusted wildcard grants global scope under configured policy. Email/display name are presentation data, never assignment keys.

| Action | Reviewer | Campaign admin | Approver | Auditor | Operator |
| --- | --- | --- | --- | --- | --- |
| Read/decide assigned pending review | Read/decide | Scoped read; decide only with separate reviewer eligibility | Approval-item read | Authorized read only | No full evidence by default |
| Create/manage campaign and assignments | No | Yes | No | No | No |
| Approve direct-path remediation | No | No | Yes, not own review | No | No |
| Audit/export | No by default | Campaign scope | Approval scope | Authorized scope | Redacted operations only |
| Health/integrations/reconciliation | No | No | No | No | Yes |

Multiple roles are additive, but every mutation checks the role and resource anew. Reviewer-pool membership and individual assignment are separate. An unassigned review is available to the campaign pool; reassignment removes the former reviewer's access. Auditor reads cannot mutate. Neither an operator nor AI can bypass remediation approval.

## API and acceptance rules

Current list routes use bounded offset pages and stable ordering; apply authorization predicates **before** filters, totals, and aggregates. Validate filter enums and never accept SQL or arbitrary sort expressions. Return UTC timestamps and format in the browser. The current API has route-specific error shapes; a future normalized `/api/v1` contract should add stable error codes, opaque filter-bound cursors, `Idempotency-Key` for retriable creates/exports, and version checks for metadata edits without pretending they exist today.

For each endpoint, test `401` unauthenticated, `403` wrong role or scoped `404`, guessed cross-account/review IDs, filtered totals, concurrent mutations, stale pins, replay, and failure states. Decisions and workflow changes record immutable actor, entity, time, outcome, and request ID; operational logs omit secrets and raw policies. Verify that review detail and export use the **pinned** manifest, not a mutable current record; downloads require scope before file access. Worker result states must distinguish approval, action, reconciliation, and verified outcome. The frontend exposes uncertainty rather than treating one removed grant path as total access removal.

When changing a route or response, update `api/review_service.py`, BFF allowlist in `frontend/src/app/api/backend/[...path]/route.ts`, frontend types, generated OpenAPI/schema, and API/UI/security tests. Browser journeys with mocked BFF responses verify UI behavior and accessibility, not real OIDC, API authorization, worker execution, or AWS readiness. See [frontend setup](../frontend/README.md) and [deployment acceptance](production-readiness.md).
