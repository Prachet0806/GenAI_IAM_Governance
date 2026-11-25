# Product validation protocol

Status: no customer sessions, buyer commitments, approved provider evaluation, or reviewer pilot are recorded. Local tests and mocked browser journeys cannot pass these gates.

## Release 1: deterministic workflow

Recruit an IAM administrator, actual access reviewer, audit consumer, and budget owner. Record organization/account scale, review cadence and volume, incumbent workflow, error owner, procurement and data constraints. Obtain permission to observe representative non-secret examples. Before showing the prototype, measure the same cases in their existing workflow: time, wrong principal/policy conclusions, missed uncertainty, escalation quality, and evidence-assembly effort.

| Participant | Observed task | Correct outcome |
| --- | --- | --- |
| Administrator | Inspect complete, failed-later, and invalidated scans; compare same-account/scope published snapshots. | Separate collection, publication, coverage, age and current eligibility; identify added/removed/changed observed paths. |
| Reviewer | Decide or escalate direct, group-derived, missing-document and stale/invalidated paths with AI off. | Identify principal/source/attachment, frozen version and statement, rule reason, unknown effective access, and appropriate escalation. |
| Auditor | Reconstruct a decision from pinned manifests, observation, assessment, comment and invalidation; verify CSV/JSON/evidence/manifest artifacts. | Independently trace history and identify legacy proof that is unavailable. |

For each task record completion, elapsed time, errors, missed evidence, escalation, navigation friction, and the participant's explanation of what the product proves. A quick wrong decision fails. Ask the buyer about current cost, recurring volume, alternatives (including AWS-native and spreadsheet flows), integrations, residency, deployment, security review, and a concrete pilot owner/data/date/success criterion. Keep one dated, redacted result per organization with scenario IDs, baseline/prototype comparison and evidence links; mark each observation, participant claim, or inference.

Release 1 needs correct role journeys with authorized access in managed AWS/OIDC staging, PostgreSQL and hosted CI at the release commit, and documented buyer interest in recurring value. Record an owner-approved go/no-go decision and unresolved defects before claiming shipment.

## Release 2: reviewer study

Predeclare a minimum improvement in **time to a correct, defensible review** and stop conditions for wrong path/principal/source, false reassurance, missed uncertainty, or privacy breach. Use realistic direct/group/trust/Identity Center/missing/stale bundles. Counterbalance deterministic UI versus UI plus explanation/Q&A across reviewers; an independent adjudicator scores source/path identification, uncertainty, escalation, corrections, and decision quality only when business need is known. Measure adoption, trust calibration, provider cost, and buyer feedback. Freeze case selection, reviewer count, effect estimate, variance and power calculation before full recruitment; a model-case count is not a human-study sample. See [AI governance](ai-governance.md) for the separate provider quality and safety gate.
