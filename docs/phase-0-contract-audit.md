# Phase 0 contract and compatibility audit

Checked 2026-11-21 against local `upgrade` at `7a895f1`; local `main` is `32df563`. Latest migration family is `0011_remediation_approval_declines`. The worktree already had unrelated untracked `docs/local-pre-staging-acceptance.md`. This is a source audit and design freeze record, not P0.1 sign-off or proof from live AWS, provider, hosted CI, or PostgreSQL concurrency.

## Verified implementation baseline

| Source | Verified behavior | Required change or decision |
| --- | --- | --- |
| `common/repo.py:start_discovery_attempt` | Inserts a `RUNNING` row and advances a source attempt head while retaining the publication pointer. | Keep per-account/scope fencing. |
| `common/repo.py:publish_discovery_snapshot` | Checks the attempt head, writes snapshot/observations/pointer, then marks `COMPLETE` in the publication transaction. Losing runs become `INCOMPLETE` with `reason=superseded`. | No independent persisted collection success for a loser. Add a validated completion receipt before publish; do not interpret old `INCOMPLETE` as `SUCCEEDED`. |
| `common/source_scanner.py:publish_source` and `lambdas/identity_discovery/handler.py:discover_identities` | Collect in memory, construct coverage and call publication; errors mark the run `FAILED`. | Define durable validation boundary, zero-finding proof, crash recovery, and errors after collection but before publication. |
| `sql/migrations/0001_baseline.sql`, `0002_grant_evidence.sql` | `discovery_runs` has a single combined status; published snapshots and source pointers are separate. | New receipt/status storage needs the next ordered additive migration and SQLite/PostgreSQL parity. |
| `common/evidence.py:grant_observation` | Stores stable grant/observation IDs, source and attachment IDs, optional policy version, document hash and observation time. | Reject missing metadata and validate exact grant/attachment/version chain when assessment is consumed. |
| `common/repo.py:store_grant_risk_assessment` | Policy assessment ID uses policy ID/hash/rule version; grant assessment ID uses observation/rule version, then links the policy assessment. | Keep valid policy-level deduplication, but check the grant-level binding to the precise frozen observation and attachment before review/AI use. |
| `lambdas/risk_evaluation/handler.py:assess_policy` | Broad string triage; unsupported constructs can map to legacy HIGH and unknown exact actions can map LOW. | Implement the reviewed severity/confidence/completeness rubric under a new rule version; retain old pins. |
| `lambdas/identity_center_discovery/handler.py` | Some missing managed policy documents and unresolved customer references are retained as `MISSING` evidence with a reason. | Separate collection success from document coverage and parser interpretability. |
| `common/ai_artifacts.py` | Explanation context and eligibility depend on legacy risk; provider request structure is currently limited. | Treat new payload as an additive read path and check actual final provider payload against versioned approval before any expanded provider input. |

## Consumer dependency map

| Consumer | Current dependency | P0.4 compatibility check |
| --- | --- | --- |
| `lambdas/generate_reviews/handler.py` and `common/repo.py:list_assessed_grants` | Select assessed grant observations and legacy `risk_level` to create pinned reviews. | Keep routing behavior until new status mapping is explicitly accepted; verify old and new rule versions. |
| `api/review_service.py` | Exposes legacy `risk_level`, reason and assessment IDs on review reads/filtering. | Add nullable structured fields with old-row labeling; account and reviewer access stay server-side. |
| `frontend/src/lib/api/types.ts` and `frontend/src/components/review-workspace.tsx` | Type and render legacy risk as a badge/callout. | Explain known concerning pattern and incomplete assessment separately; no partial case should appear fully evaluated. |
| `common/ai_artifacts.py` and `lambdas/ai_explanation/handler.py` | Explanation eligibility and prompt context use pinned legacy risk and IDs. | Preserve disabled/fallback path; do not let a new uncertain assessment yield reassuring generated prose. |
| `reports/export_audit.py` | Exports legacy risk and pinned assessment IDs. | Export pinned historical facts and current eligibility/invalidation annotations as distinct fields. |
| `frontend/openapi.json`, `frontend/src/lib/api/schema.d.ts`, `docs/frontend-api-contract.md` | Generated/documented API surface. | Regenerate and test if response schemas change. |

## P0.1 decisions and exit

The companion contracts are [IAM semantics](iam-semantics-contract.md), [risk assessment](risk-assessment-model.md), and [evidence lifecycle](evidence-lifecycle.md). The local implementation uses a durable collection receipt and canonical manifest, with legacy review and export fields retained. Before P0.1 sign-off, independently review the severity table and allowed claims against a labeled scenario corpus; decide whether unpublished observation bodies must also be durable; validate the manifest test vectors with a second implementation; and exercise old API/export consumers and PostgreSQL behavior. Recheck the target commit and migration head because both can change.

The evidence lifecycle, rule-versioned assessment, and additive read/UI compatibility have local implementations. Q&A, attack paths and AI-assisted remediation have no Phase 0 implementation scope.

## Local implementation progress after this baseline audit

Migrations `0012_collection_receipts` through `0014_evidence_invalidations`, `common/evidence_manifest.py`, and `common/policy_assessment.py` now implement the first single-source receipt/manifest and rule-versioned triage path. The scanner commits a validated receipt before publication. A grant assessment carries its own attachment/version identity and completeness; policy-level assessment deduplication remains document-scoped. An authorized administrator can add an immutable snapshot invalidation, which blocks current eligibility. The review API and workspace expose structured uncertainty alongside legacy routing, and audit JSON/CSV exports label pinned hashes and invalidations separately from eligibility at export time. This is local source status; independent corpus approval, PostgreSQL runtime, hosted CI, real AWS, and provider studies remain open.
