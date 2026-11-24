# Release 1 product validation

Status: **protocol ready; no customer sessions or buyer commitments recorded**. Local automated tests and mock browser journeys do not satisfy this gate.

## Participants and baseline

Recruit at least one IAM administrator, one person who actually certifies access, one audit consumer, and the budget owner or procurement sponsor. Record their organization type, account count, IAM review cadence, grant-path volume, incumbent workflow, and the person who owns errors. Obtain permission to observe the session and use representative, non-secret policy examples.

Before showing the prototype, have each participant complete or explain the same review in their current workflow. Record task time, wrong-principal or wrong-policy conclusions, missed uncertainty, escalation quality, and time spent collecting evidence. Ask which part is expensive enough to pay to reduce.

## Observed tasks

1. **Administrator:** inspect a complete scan, a failed later attempt, and an invalidated publication. Explain separately what was collected, what was published, the declared coverage, the observation window, and whether a campaign can start. Compare two published snapshots of the same account and source scope and identify one added, removed, and changed observed grant path.
2. **Reviewer:** decide or escalate a direct policy path, a group-derived path, a missing-document path, and a stale/invalidated path. Identify principal, source relationship, attachment, frozen policy version, matched statement, rule reason, and what effective access remains unknown. Use the product with AI disabled.
3. **Auditor:** start from a recorded decision, reconstruct the pinned source/review manifests, frozen observation and assessment, decision/comment and invalidation history, then independently verify and inspect the CSV, JSON, evidence, and manifest export artifacts. Identify a legacy review whose proof is unavailable.

For each task record completion, elapsed time, wrong conclusions, missed evidence, appropriate escalations, navigation friction, and the participant's own explanation of what the product proves. Treat a fast but wrong decision as a failure. Compare results with the baseline workflow on the same cases.

## Buying and operating questions

Ask the budget owner for the current review cost, recurring review volume, procurement/security constraints, data residency and provider restrictions, required integrations, preferred deployment model, and a concrete pilot commitment (owner, data, start date, success criterion). Compare the deterministic evidence screen against the current AWS-native or spreadsheet workflow and, only after that, a conversational explanation concept. Record the stated alternative and reason for choosing or rejecting this product.

## Result record

Create one dated result per organization with: participant roles, scenario IDs, baseline and prototype times, errors, escalations, missing features, deployment constraints, buyer response, and evidence link. Redact names and account identifiers. Mark each result `observed`, `participant claim`, or `inference`; never substitute an internal demo for an external observation.

## Release decision

Release 1 requires the role tasks to succeed with correct uncertainty and authorized access in a managed AWS/OIDC staging environment, plus PostgreSQL and hosted CI at the target commit. The product claim requires documented buyer interest and recurring operating value. Record a go/no-go decision with unresolved failures and owner before claiming Release 1 shipped or funding Release 2 AI expansion.
