# Frontend API contract and permission matrix

Status: proposed contract, grounded in the current local checkout. Some workflow additions are uncommitted in this working tree. Existing routes are marked **Present in local source**; new routes proposed below require backend work. Presence in source does not mean tested, deployed, or production-ready.

## 1. Current-state baseline

The local checkout contains these application routes today:

| Method and route | Current behavior | Authorization |
|---|---|---|
| `GET /health` | Service health response | No OIDC dependency in the route |
| `GET /reviews/queue` | Current reviewer's pending queue; bounded `limit`/`offset` pagination, no cursor/filter parameters | Valid OIDC token, reviewer group, campaign reviewer pool; review assignment restricts access when present |
| `GET /reviews/{review_id}` | Returns one review, frozen grant/policy/risk evidence, evidence state, `review_scope`, `principal_access_status: not_evaluated`, validated AI artifact projection with labelled legacy fallback, assignment/deadline/exception state | Valid OIDC token, reviewer group, campaign membership, and per-review assignment if present |
| `POST /reviews/{review_id}/decision` | Records `APPROVED` or `REVOKED`; revocation requires a comment; duplicate/racing decisions conflict | Valid OIDC token, reviewer group, campaign membership, and per-review assignment if present; campaign must be open and review must not have an open exception |
| `POST /campaigns/{campaign_id}/reviewers` | Assigns a reviewer subject to a campaign; duplicate assignment is reported | Valid OIDC token and campaign-admin group |
| `GET /campaigns/{campaign_id}` | Returns one campaign's snapshot and workflow metadata | Campaign admin, or reviewer assigned to the campaign |
| `GET /campaigns/{campaign_id}/events` | Returns bounded workflow-event pages using `limit` and `offset` | Campaign admin, or reviewer assigned to the campaign |
| `POST /ai/jobs/{job_id}/retry` | Queues an audited next-generation retry of a failed explanation job | Campaign-admin group; provider and privacy gates enabled |
| `POST /campaigns/{campaign_id}/state` | Opens, pauses, resumes, or closes a campaign subject to lifecycle constraints | Campaign-admin group |
| `POST /campaigns/{campaign_id}/owner` | Changes campaign owner | Campaign-admin group |
| `POST /campaigns/{campaign_id}/deadline` | Sets campaign deadline; requires a future timezone-aware timestamp | Campaign-admin group |
| `POST /reviews/{review_id}/assignment` | Assigns/reassigns a pending review to a reviewer already in the campaign pool | Campaign-admin group |
| `POST /reviews/{review_id}/deadline` | Sets deadline on a pending review | Campaign-admin group |
| `POST /reviews/{review_id}/exception` | Opens an exception on an assigned review; blocks reviewer decision while open | Reviewer group and campaign/review assignment |
| `POST /reviews/{review_id}/exception/resolve` | Resolves an open exception with a reason | Campaign-admin group |
| `POST /reviews/{review_id}/remediation-approval` | Approves/renews remediation for eligible revoked review, bound to the current eligible snapshot | Valid OIDC token, approver group, independent approver check |

Campaign generation is currently a worker operation, not a user-facing API. It selects an eligible published snapshot, optionally by `account_id`, requires complete risk assessments, and creates reviews pinned to snapshot evidence. Routes still missing include paginated/filterable campaign and review lists, campaign creation, reviewer-pool listing/removal, discovery and snapshot readiness, review history, remediation approval queue and execution outcomes, scoped audit/export access, and operations status. The current queue and events routes support bounded offset pages; stable cursor pagination remains a proposed improvement for changing queues.

The checkout has uncommitted campaign, source, and AI-platform changes through migration `0008_ai_job_recovery`. They add campaign lifecycle and reviewer queues, source-specific evidence and risk, validated AI artifacts, and audited failed-job retry. This local contract does not establish deployment or hosted CI status.

## 2. Authorization model

### Identity

- Authenticate through the organization OIDC provider. The API verifies signed access tokens using configured issuer, audience, HTTPS JWKS URL, expiry, and subject.
- Use the immutable OIDC `sub` as the actor and assignment key. Email and display name are presentation attributes, not authorization identifiers.
- The current API reads a configurable group claim (default `groups`) and requires configured group names. For the frontend, expose a normalized `/me` response rather than making the browser interpret provider-specific claims.
- Prefer a backend-for-frontend session with secure, HTTP-only cookies for the web app. Never persist access tokens in local storage.

### Roles and permissions

| Capability | Reviewer | Campaign admin | Remediation approver | Auditor | Platform operator |
|---|---:|---:|---:|---:|---:|
| Read own profile and effective app permissions | Yes | Yes | Yes | Yes | Yes |
| Read review queue | Assigned campaigns only | Campaigns they administer | Eligible remediation items only | Authorized read-only scope | Operational need only |
| Read full frozen review evidence | Assigned campaigns only | Campaigns they administer | Items awaiting approval | Authorized read-only scope | No by default |
| Record approve/revoke decision | Assigned pending items | Only if separately assigned reviewer | No | No | No |
| Create campaign | No | Yes | No | No | No |
| Change campaign lifecycle / owner / deadline | No | Yes | No | No | No |
| Assign / reassign reviewers | No | Yes | No | No | No |
| Approve remediation | No | No | Yes, excluding own review | No | No |
| Read audit history / download exports | No by default | Campaign scope | Approval scope | Yes, authorized scope | Operational logs only |
| Read platform health / integration status | No | No | No | No | Yes |
| Change runtime security configuration | No | No | No | No | Outside this UI in MVP |

These are application permissions, not claims that users possess corresponding AWS permissions. Every endpoint must authorize the actor and resource server-side before returning rows, counts, or aggregates. Hiding navigation or buttons is not an access control.

### Separation-of-duties rules

1. A reviewer can decide only a pending review in a campaign to which their `sub` is assigned.
2. A remediation approver must belong to the configured approver group and must not be the reviewer recorded on that review.
3. Campaign administrators cannot decide reviews solely by virtue of being administrators; they need reviewer assignment and reviewer-group permission.
4. Auditors receive read-only access. They cannot create, assign, decide, approve, or mutate evidence.
5. Operators receive only operational information. No operator UI action can change IAM or bypass the remediation worker.
6. If a person holds multiple roles, permissions are additive but each operation still checks its own role and resource scope.

## 3. API conventions

### Base and versioning

Use `/api/v1` for new frontend-facing routes. Existing unversioned routes can remain as compatibility routes while the UI migrates. Publish an OpenAPI schema and generate a typed frontend client from it. Do not let the UI query the database or depend on worker internals.

### Pagination and filtering

Every list endpoint uses server-side pagination and stable ordering:

```json
{
  "items": [],
  "page": {"limit": 50, "next_cursor": null},
  "total": 0
}
```

- Default `limit=50`, maximum `limit=200`.
- Cursor is opaque and bound to the active filter and sort. Return `400 INVALID_CURSOR` if reused with different filters.
- Use stable sorting with a unique ID as the final tie-breaker.
- Apply authorization predicates before filtering, counting, or aggregation. Totals must never include inaccessible campaigns or reviews.
- Validate filter values against documented enums. Do not accept SQL fragments or arbitrary sort expressions.

### Common error response

```json
{
  "error": {
    "code": "SNAPSHOT_NOT_ELIGIBLE",
    "message": "A complete current AWS snapshot is required.",
    "request_id": "...",
    "details": {}
  }
}
```

Use `401` for missing/invalid authentication, `403` for authenticated but unauthorized, `404` for missing or intentionally undisclosed resources, `409` for state/version conflicts, `422` for invalid input, and `503` for unavailable dependencies. The UI should branch on stable `code`, not parse message text.

### Mutations and audit

- Mutations are authenticated and authorized at the API; record actor `sub`, event time, entity, before/after values where appropriate, and request ID.
- Use an `Idempotency-Key` for create/export operations that may be retried. Decisions remain conditional on the review still being pending.
- Use `ETag`/`If-Match` or an explicit `version` for campaign metadata changes. Return `409 VERSION_CONFLICT` when stale.
- Return UTC ISO-8601 timestamps. The UI formats them in the user's locale.

## 4. Proposed endpoint catalog

### P0 — Identity and authorization bootstrap

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /api/v1/me` | `sub`, display name, email if available, groups normalized to app roles, feature flags | Any authenticated user |
| `GET /api/v1/me/permissions` | Resource-independent action permissions and role names | Any authenticated user |

Example `/me` response:

```json
{
  "sub": "oidc-subject",
  "display_name": "Alex Reviewer",
  "roles": ["reviewer", "campaign_admin"],
  "permissions": ["reviews:read_assigned", "reviews:decide", "campaigns:read", "campaigns:create", "campaigns:assign"]
}
```

Do not return raw tokens or assume that an email address is unique or immutable.

### P0 — Reviewer workspace

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /api/v1/reviews` | Queue of reviews visible to the current reviewer; filters: `campaign_id`, `status`, `risk_level`, `account_id`, `principal`, `due_before`; stable cursor | Reviewer group; assigned campaign only |
| `GET /api/v1/reviews/{review_id}` | Review detail with pinned evidence and authorization-safe context | Reviewer group; assigned campaign only |
| `POST /api/v1/reviews/{review_id}/decision` | Existing decision operation, versioned under v1 | Reviewer group; assigned pending item |
| `GET /api/v1/reviews/{review_id}/history` | Decision and workflow history, including actor and timestamps | Reviewer assigned to campaign; admins/auditors by scope |

Local-source status: `GET /reviews/queue` supports bounded `limit`/`offset` pages but has no stable cursor or filters. `GET /reviews/{review_id}` and `POST /reviews/{review_id}/decision` exist unversioned. The versioned paths above are the recommended frontend contract and require route migration/compatibility work.

Queue item fields: `review_id`, `campaign_id`, `campaign_name`, `principal`, `grant_name`, `grant_type`, `risk_level`, `status`, `assigned_reviewer_sub`, `due_at`, `created_at`, `snapshot_id`.

Review detail must include `review_scope`, grant/source provenance, policy version/hash and policy document when permitted, risk assessment/rule version, snapshot ID/time/account/scope, current evidence state, decision history, AI explanation provenance if available, and `principal_access_status: "not_evaluated"`. Never label a path-level decision as removal of all effective access.

Decision request:

```json
{"decision": "REVOKED", "comment": "No longer required", "version": 1}
```

`comment` is required for `REVOKED`. Return `409 REVIEW_ALREADY_DECIDED` or `409 VERSION_CONFLICT` on concurrent changes. Preserve the existing rule that decisions are not reversible through a second decision; any correction needs an explicit audited workflow.

### P0 — Minimum campaign creation and reviewer assignment

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /api/v1/campaigns` | Campaign list with status, account, owner, progress summary, and snapshot | Campaign admin for managed scope; reviewer for assigned campaigns; auditor for authorized read-only scope |
| `GET /api/v1/campaigns/{campaign_id}` | Campaign detail, immutable snapshot binding, current lifecycle and counts | Same resource-scoped rules |
| `POST /api/v1/campaigns` | Create from an eligible published snapshot; supports explicit `account_id` and supported `source_scope` | Campaign admin |
| `GET /api/v1/campaigns/{campaign_id}/progress` | Counts by review status/risk and assignment coverage | Campaign admin; auditor read-only |
| `GET /api/v1/campaigns/{campaign_id}/assignments` | Assigned reviewer subjects and workload counts | Campaign admin; auditor read-only if authorized |
| `POST /api/v1/campaigns/{campaign_id}/assignments` | Assign one or more reviewers to whole campaign or explicit review IDs, depending on supported backend model | Campaign admin |
| `DELETE /api/v1/campaigns/{campaign_id}/assignments/{reviewer_sub}` | Remove assignment only if pending work is safely reassigned or explicitly unassigned | Campaign admin |

Local-source status: `GET /campaigns/{campaign_id}` and `POST /campaigns/{campaign_id}/reviewers` exist unversioned. There is no campaign list, progress endpoint, interactive create endpoint, or reviewer-pool listing/removal endpoint. Campaign creation is currently performed by the worker.

Campaign create request:

```json
{
  "name": "Q4 Access Certification",
  "account_id": "123456789012",
  "source_scope": "IAM_USER_POLICY",
  "owner_sub": "admin-sub",
  "due_at": "2026-12-15T00:00:00Z"
}
```

Creation must fail closed with `409 NO_ELIGIBLE_SNAPSHOT`, `409 SNAPSHOT_RISK_INCOMPLETE`, `422 UNSUPPORTED_SCOPE`, or `409 CAMPAIGN_ALREADY_EXISTS_FOR_SNAPSHOT` as applicable. The response includes the selected snapshot ID and created review count. The current worker generates an automatic campaign name and accepts `account_id` as an event value; an interactive create API and metadata are new functionality.

### P0 — Discovery and snapshot readiness

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /api/v1/snapshots` | Published snapshots, filtered by account/scope and paginated | Campaign admin; auditor read-only |
| `GET /api/v1/snapshots/{snapshot_id}` | Snapshot metadata, coverage, publish time, source and account | Campaign admin; auditor read-only |
| `GET /api/v1/snapshots/{snapshot_id}/readiness` | Eligibility and human-readable blockers for campaign/remediation use | Campaign admin; auditor read-only |
| `GET /api/v1/discovery-runs` | Attempts including RUNNING, COMPLETE, INCOMPLETE, FAILED and superseded context | Campaign admin; operator; auditor read-only |
| `GET /api/v1/discovery-runs/{run_id}` | Run detail and failure/coverage summary | Same |

Snapshot readiness must distinguish last published snapshot from latest attempt. Return explicit booleans/reasons such as `is_published`, `is_latest_attempt`, `is_complete`, `risk_assessments_complete`, `is_fresh`, `blocked_by_newer_attempt`, and `eligible_for_campaign`/`eligible_for_remediation`. Include account and declared source scope. Avoid a single ambiguous `healthy` value.

### P1 — Campaign lifecycle and allocation

| Endpoint | Purpose | Access |
|---|---|---|
| `PATCH /api/v1/campaigns/{id}` | Change owner, name, due date, or lifecycle state with version check | Campaign admin |
| `POST /api/v1/campaigns/{id}/assignments` | Assign/reassign reviewers to review subsets | Campaign admin |
| `PATCH /api/v1/reviews/{id}/assignment` | Assign, reassign, or clear one review's assignee, with event record | Campaign admin |
| `POST /api/v1/reviews/{id}/exceptions` | Open exception with reason and owner | Campaign admin; reviewer may request, if enabled |
| `POST /api/v1/reviews/{id}/exceptions/{exception_id}/resolution` | Resolve exception with disposition and comment | Campaign admin |

The current local source already contains unversioned lifecycle routes: `GET /campaigns/{id}/events`, `POST /campaigns/{id}/state`, `/owner`, `/deadline`, and `POST /reviews/{id}/assignment`, `/deadline`, `/exception`, `/exception/resolve`. The v1 routes above are a normalization proposal, not implemented paths. The worktree's campaign-wide membership (`campaign_reviewers`) and per-review assignment (`assigned_reviewer_sub`) have different semantics. Define who may see unassigned work and how reassignment affects started reviews. Queue and event reads now offer bounded offset pagination; cursor pagination remains a proposed production improvement.

### P1 — Remediation approvals and execution status

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /api/v1/remediation/approvals` | Queue of revoked reviews eligible/pending approval, with eligibility reasons | Approver group |
| `GET /api/v1/remediation/{review_id}` | Approval, worker claim, dry-run/live mode, and execution outcome | Approver; reviewer/auditor read-only by authorized scope |
| `POST /api/v1/remediation/{review_id}/approval` | Existing approval operation, versioned under v1 | Approver group; different `sub` from reviewer |
| `POST /api/v1/remediation/{review_id}/approval-decision` | Optional explicit rejection if product supports reject/decline | Approver group; requires new audited state model |

Local-source status: `POST /reviews/{review_id}/remediation-approval` exists unversioned. The queue, explicit rejection, and worker outcome endpoints are not present.

Eligibility response must state exact reasons, including unsupported grant type, legacy/unpinned evidence, stale or superseded snapshot, no longer-current grant, non-revoked review, missing independent reviewer identity, self-approval, dry-run configuration, and production live-remediation block. Approval is not proof that AWS action succeeded. The worker result must separately report queued/running/succeeded/failed/reconciled/skipped and the verified direct attachment outcome. Never claim that the principal lost all effective access.

### P1 — Audit and export access

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /api/v1/audit/campaigns/{campaign_id}` | Paginated campaign events and decision history | Auditor; campaign admin for own campaign |
| `GET /api/v1/exports` | List authorized export runs and manifests | Auditor; campaign admin within scope |
| `POST /api/v1/exports` | Request an export for an authorized campaign/scope | Auditor; campaign admin within scope |
| `GET /api/v1/exports/{export_id}` | Export state, counts, artifact hashes and storage metadata | Same |
| `GET /api/v1/exports/{export_id}/download` | Authenticated download or short-lived scoped URL | Same |

Do not expose arbitrary filesystem paths or unrestricted S3 URLs. Bind exports to explicit authorized campaign/account scope, audit each request and download, and return the manifest/hash so the user can verify integrity. Current export code generates artifacts for all available review rows; authorization-scoped export retrieval is additional backend work.

### P2 — Operations

| Endpoint | Purpose | Access |
|---|---|---|
| `GET /api/v1/operations/health` | Liveness/readiness and dependency status separated | Platform operator |
| `GET /api/v1/operations/integrations` | Sanitized connectivity/configuration state, never secret values | Platform operator |
| `GET /api/v1/operations/jobs` | Discovery, evaluation, campaign, export, remediation job state | Platform operator |
| `GET /api/v1/operations/audit` | Operational event stream with filters and pagination | Platform operator; sensitive fields redacted |

Operations endpoints require a production deployment and job/event model. Do not build simulated controls that imply a worker, queue, scheduler, alert, or secret manager exists when it does not.

## 5. Screen-to-endpoint map

| Screen | Primary endpoint dependencies |
|---|---|
| Sign-in / app bootstrap | OIDC flow, `GET /me`, `GET /me/permissions` |
| Reviewer home / My reviews | `GET /reviews`, `GET /campaigns` (assigned subset) |
| Review detail | `GET /reviews/{id}`, `GET /reviews/{id}/history`, `POST /reviews/{id}/decision` |
| Campaign list / detail | `GET /campaigns`, `GET /campaigns/{id}`, `/progress`, `/assignments` |
| Create campaign wizard | `GET /snapshots`, `/readiness`, `POST /campaigns`, assignment endpoint |
| Assignment management | `/assignments`, assignment mutation endpoints, campaign progress |
| Remediation approvals | `GET /remediation/approvals`, `GET /remediation/{id}`, approval mutation |
| Auditor workspace | campaign/audit endpoints, exports list/create/detail/download |
| Operations | health, integrations, jobs, operational audit |

## 6. Delivery gates

### Gate A — Contract before business UI

- Reconcile local working-tree code and migrations with the intended branch/release baseline.
- Decide campaign-level versus per-review assignment semantics.
- Publish OpenAPI schemas, permission matrix, stable errors, and examples.
- Confirm policy-document visibility and export/download authorization.
- Confirm OIDC role/group mapping and BFF/session deployment model.

### Gate B — Usable reviewer MVP

- Implement identity bootstrap, reviewer queue, detail/history, and decision endpoints.
- Implement minimal campaign create and assignment so a reviewer can receive real work; alternatively document a controlled operator-run campaign process as a temporary dependency.
- Review detail is snapshot-pinned and clearly presents grant-path scope and effective-access uncertainty.
- Enforce assignment authorization, audit decisions, and concurrency conflicts server-side.

### Gate C — Campaign operations

- Add discovery/snapshot readiness, campaign progress, assignment lifecycle, due dates, and reassignment semantics.
- Test account scoping, failed/newer attempts, incomplete runs, and risk-incomplete snapshots.

### Gate D — Approval, audit, and operations

- Expose remediation eligibility and worker outcomes separately from approval.
- Add scoped immutable audit and export retrieval.
- Add operational endpoints only when deployment observability exists.

## 7. Acceptance checks for every endpoint

1. Unauthenticated request returns `401`; authenticated wrong-role request returns `403` (or scoped `404` where existence disclosure is undesirable).
2. A reviewer cannot list, fetch, or decide another campaign's review by guessing an ID.
3. List totals, dashboard aggregates, and cursor pages contain only authorized resources.
4. Concurrent decision or metadata updates return stable conflict codes and do not create duplicate events.
5. Audit rows include actor, resource, timestamp, and outcome; secrets, tokens, and raw policy documents are not copied into operational logs.
6. Snapshot, grant path, risk assessment, and campaign bindings are consistent; UI-facing evidence comes from the pinned review, not a mutable current record.
7. All list endpoints are paginated, bounded, filter-validated, and deterministically ordered.
8. Export authorization is checked before file access; downloads are attributable and scoped.
9. Error responses expose actionable state without leaking policy data or whether inaccessible resources exist.
10. Contract tests cover allowed and denied role/resource combinations, stale evidence, replay/idempotency, and failure states.

## 8. Recommended build order

1. **Contract and authorization:** settle identity mapping, assignment model, API schemas, and errors.
2. **Reviewer flow plus minimum campaign setup:** ship the evidence-centered queue and decision experience, with just enough campaign creation and assignment to supply real work.
3. **Campaign administration:** snapshot readiness, lifecycle, reviewer allocation, progress, deadlines, and exceptions.
4. **Remediation approvals:** eligibility queue and independent approval, followed by observable worker outcomes.
5. **Audit and exports:** scoped immutable history and verifiable artifact retrieval.
6. **Operations:** only after deployment jobs, integrations, and alerting are defined.

