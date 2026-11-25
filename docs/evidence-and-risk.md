# Evidence and risk contract

Status: the single-source receipt/manifest and `policy-risk-v6` triage paths are implemented locally. Independent IAM review, PostgreSQL concurrency at the release revision, hosted CI, and live AWS acceptance remain open. This contract describes **observed grant paths and document triage**, not a principal's effective AWS permissions.

## Collection and publication

Every discovery attempt is keyed by account and declared source scope. The attempt head names the newest run; the publication pointer names the last committed snapshot. Collect all pages and required documents, verify the account, validate identities, coverage, hashes, duplicate observations, and counts, then persist a validated completion receipt before publication. A zero-finding success requires explicit complete pagination and coverage with zero counts. Missing referenced documents may remain visible as `MISSING` evidence; failed pagination or validation cannot be published.

Publication compares the attempt with the current head **inside its transaction**, then atomically writes the source snapshot, observations, pointer, and completion status. A newer failed or running attempt retains the previous publication for history but blocks new campaigns and live remediation. A superseded attempt cannot publish later; recovery starts a new attempt. Source scopes publish independently, so their snapshots are not one simultaneous AWS transaction.

| Collection | Publication | Interpretation |
| --- | --- | --- |
| `RUNNING` | `NOT_PUBLISHED` | No completed proof. A crash can leave this persisted state. |
| `SUCCEEDED` | `CURRENT_PUBLISHED` / `PREVIOUSLY_PUBLISHED` | Validated and committed, then possibly replaced. |
| `SUCCEEDED` | `SUPERSEDED_BEFORE_PUBLICATION` / `REJECTED` | Receipt survives, but no snapshot was published. |
| `FAILED` | `NOT_PUBLISHED` | Collection or validation failed. |
| `UNKNOWN_LEGACY` | `UNKNOWN_LEGACY` | Old rows cannot prove the collection outcome. |

Legacy `discovery_runs.status` combines these axes. A pre-`0012` `INCOMPLETE`/`superseded` row proves loss of publication eligibility, **not** successful collection; do not infer success from logs. Migration `0012_collection_receipts` adds the append-only per-attempt receipt with account, scope, validation version, completion time, pagination proof, principal/grant/missing-document counts, and observation digest. It does not retain unpublished observation bodies. Migration `0014_evidence_invalidations` adds immutable defect annotations that block current eligibility without rewriting historical evidence.

## Frozen evidence and claims

A `SINGLE_SOURCE` evidence-set manifest binds account, scope version, published snapshot, observation window, coverage, missing references, schema version, and hash. A review manifest pins that source manifest, grant, observation, attachment, policy version/hash, policy and grant assessments, and rule version. Current eligibility and invalidation are separate projections. Cross-source path inference requires a separately reviewed temporal comparison and skew threshold.

Canonical manifest bytes use sorted JSON object keys, UTF-8, SHA-256, defined null/number/timestamp forms, stable-ID order for set-like arrays, and original order for statements. Reject duplicate IDs and duplicate JSON keys. Keep fixed hash vectors for Unicode, missing/null, array ordering, and equivalent serializations. Do not silently change existing stable IDs or rewrite an old review binding.

Public claims are typed `OBSERVED_FACT`, `RULE_INFERENCE`, `EXTERNAL_FINDING`, or `NOT_EVALUATED`; the current engine emits only the first two. Every inference needs exact evidence, scope, rule version, and wording. An attachment or role-trust statement is an observed relationship, not proof of authorization, business need, or safe removal. Identity Center group assignments do not expand to individual members. Boundaries, SCPs, RCPs, resource/session policies, and complete effective access are outside the current assessment.

## Policy parsing and triage

`common/policy_assessment.py` consumes the frozen account/scope/snapshot/observation/grant/source/attachment identity, policy type and version, document hash, and observation time. An absent attachment is a collection error; an unavailable version stays explicit. Textual JSON rejects duplicate keys, including nested objects. Native SDK objects cannot prove original duplicate-key absence. Preserve the source document and parse status, with zero-based statement index, optional `Sid`, exact constructs, and reason codes.

The parser recognizes identity, role-trust, and Identity Center evidence separately. Only reviewed `Version=2012-10-17` shapes can be fully supported. Other versions, invalid/empty statements, unexpected types, both positive and negative forms of an element, or unsupported constructs are retained as `UNASSESSED`, `UNSUPPORTED`, or `PARTIAL`; they never become reassuring LOW. Assess valid siblings independently. Record `NotAction`, `NotResource`, `NotPrincipal`, conditions, and explicit Deny without string-based allow/deny subtraction or assumed authorization effect.

New immutable assessment evidence records:

| Field | Meaning |
| --- | --- |
| `schema_version`, `rule_version` | Versioned interpretation; old assessments retain their original pins. |
| `risk_severity` | `CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN` document-pattern concern, not effective-access severity. |
| `assessment_status` | `SUPPORTED/PARTIAL/UNASSESSED/UNSUPPORTED` interpretation coverage. |
| `assessment_confidence` | `HIGH/MEDIUM/LOW/INSUFFICIENT` confidence in rule-based triage, not an authorization probability. |
| `evidence_completeness` | Collection/source/document coverage, interpretability, missing count, unsupported constructs, and reasons. |
| `manual_review_required`, `reason_codes[]`, `statement_refs[]` | Independent review flag, all reasons, and exact statement/document/attachment references. |

`evidence_completeness` distinguishes a complete scan with a missing document from a partial scan with a readable document. `unassessed_surfaces[]` names omitted IAM surfaces. Legacy `risk_level=HIGH/MEDIUM/LOW` remains a routing field; UNKNOWN or incomplete evidence routes safely to HIGH, while the structured fields explain why. Old HIGH rows have unknown confidence and must not be backfilled by inference.

| Pattern | Initial severity and confidence ceiling |
| --- | --- |
| Identity `Allow Action="*" Resource="*"` without restricting construct | `CRITICAL`, `SUPPORTED/HIGH` for syntax only. |
| Identity wildcard or reviewed sensitive action | `HIGH`; at most `PARTIAL/MEDIUM` when resource or condition semantics are unresolved. |
| Reviewed exact mutating action or read action with `Resource="*"` | `MEDIUM` unless a higher pattern applies. |
| Reviewed narrow read-only syntax, complete relevant document | `LOW/SUPPORTED/HIGH`; partial source coverage still needs review. |
| Broad or external role trust | `HIGH` for trust syntax, not proof the caller can assume the role. |
| Specific same-account trust | `MEDIUM` for observed trust syntax. |
| Missing/invalid document, unknown action, unsupported version/type, deny-only document without a supported concern | `UNKNOWN/INSUFFICIENT`, manual review. |
| Known HIGH concern plus unsupported sibling/condition/negative construct | Keep `HIGH`, lower overall status/confidence and require manual review. |

Evaluate each statement and retain all reasons; precedence changes display order only. A policy-level result may deduplicate by document hash and rule version, but each grant assessment binds its own snapshot, observation, grant, source, attachment, version, and hash. Reject binding mismatches before review or AI use. The severity table and allowed wording still require an independently labeled IAM scenario corpus.

## Acceptance and historical audit

Verify collection failure, zero findings, same-source races, crash/retry, publication rollback, old-row ambiguity, immutable pins/invalidation, and SQLite/PostgreSQL parity. Review the source/coverage semantics and canonical hash vectors independently; decide whether unpublished observation bodies must become durable before claiming that an unpublished collection is auditable.

The initial source audit was recorded on 2026-11-21 at `upgrade` `7a895f1` (local `main` `32df563`), with migrations through `0011`. It found a combined run status, no loser receipt, broad legacy risk triage, and consumers tied to `risk_level` in campaign generation, API, UI, AI, and exports. Local migrations `0012`–`0014` and `policy-risk-v6` address those paths; this historical audit is not sign-off for a later commit. Recheck the target revision, migration head, old readers, and PostgreSQL behavior before release.
