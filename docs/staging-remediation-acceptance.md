# Staging remediation acceptance

The code permits live IAM mutation only in APP_ENV=staging; production remains
blocked. This document is the operator acceptance record template. Local tests
do not establish that a staging AWS run, independent security review, or
production release gate has passed.

## Allowed paths and outcome

| Grant path | AWS action | Scope |
|---|---|---|
| DIRECT_MANAGED IAM user policy | DetachUserPolicy | One reviewed user attachment |
| DIRECT_INLINE IAM user policy | DeleteUserPolicy | One reviewed user inline policy |

Group, role, trust, and Identity Center paths have no live action in this
worker. A verified path removal does not establish that the principal lost the
same effective permission through another path.

## Independent gates

1. Use a dedicated staging AWS account and restricted remediation credentials.
   Record the account ID, credential role, operator, change ticket, and planned
   policy/user pair. Give the worker only the IAM read calls it uses plus
   iam:DetachUserPolicy and/or iam:DeleteUserPolicy on the approved targets.
2. Apply migrations through 0011_remediation_approval_declines to the staging Postgres
   database. Run the Postgres CI job and confirm its migration, concurrency, and
   evidence tests passed at the exact deployed revision.
3. Complete a source-specific AWS discovery and risk assessment. Confirm the
   published snapshot is fresh and complete, with no newer failed, incomplete,
   or running attempt. Create a review pinned to that snapshot and grant path.
4. Record a revocation through the OIDC reviewer API. A distinct authenticated
   approver records approval; inspect its immutable approval event and decision
   event ID. Old projection-only approvals are ineligible.
5. Run with DRY_RUN=true; inspect the candidate and allowlist. Set the exact
   policy name or ID in REMEDIATION_ALLOWLIST; confirm the mandatory denylist
   still blocks administrator and break-glass targets.
6. Independently review the expected preflight AWS user ID/ARN, attachment,
   policy hash/version, and action type. Record an acceptance ID tied to this
   review and change ticket. Only then set APP_ENV=staging,
   STAGING_REMEDIATION_ACCEPTANCE_ID, AWS_ACCOUNT_ID, DRY_RUN=false,
   ENABLE_REMEDIATION=true, and ALLOW_LIVE_REMEDIATION=true for the run.
7. Inspect GET /reviews/{id}/remediation and the audit export. Confirm
   PREFLIGHT_PASSED -> ACTION_REQUESTED -> ACTION_VERIFIED, the exact approval
   event, worker fencing token, and absent direct attachment. Confirm
   principal_access_status remains not_evaluated.
8. Exercise a changed policy, failed/newer scan, expired lease, concurrent
   worker, lost AWS response after action, and attachment still present after
   action. These must produce no unapproved repeat action. An uncertain or
   still-present path becomes RECONCILIATION_REQUIRED; investigate it and
   start a new snapshot/review/approval rather than reusing the old one.

Record the staging run's timestamp, revision, test results, AWS account,
review/approval/action event IDs, export manifest hash, operator, independent
approver, and disposition in the controlled change record. Remove the live
flags and acceptance ID after the run.

Production live execution requires a separate deployment and security release
decision, operational monitoring, backups, least-privilege role verification,
and controlled AWS evidence. The production code gate must not be removed
merely because local or staging tests pass.
