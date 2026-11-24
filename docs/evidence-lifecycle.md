# Phase 0 evidence lifecycle contract

Status: core single-source receipt and manifest projection implemented locally in migration `0012` and `common/evidence_manifest.py`; migration `0014` adds immutable invalidation annotations. PostgreSQL concurrency, hosted CI, and staging sign-off remain open.

## Source attempt and publication

Each attempt belongs to one account and declared source scope. The attempt head is the newest run; the source publication pointer identifies the last committed snapshot. A later failed attempt leaves the previous publication readable but blocks new campaign and live-remediation eligibility under the current rule.

| Collection outcome | Publication outcome | Meaning |
| --- | --- | --- |
| `RUNNING` | `NOT_PUBLISHED` | Collection has not completed. |
| `SUCCEEDED` | `CURRENT_PUBLISHED` | Validated collection committed as the current source snapshot. |
| `SUCCEEDED` | `PREVIOUSLY_PUBLISHED` | Validated collection was published and later replaced. |
| `SUCCEEDED` | `SUPERSEDED_BEFORE_PUBLICATION` | Validated collection lost the attempt-head race. |
| `SUCCEEDED` | `REJECTED` | Validation passed, but publication failed for another recorded reason. |
| `FAILED` | `NOT_PUBLISHED` | Collection or validation failed; no snapshot may be published. |
| `UNKNOWN_LEGACY` | `UNKNOWN_LEGACY` | Persisted history cannot prove the collection result. |

`discovery_runs.status` is a legacy combined status. `COMPLETE` plus a matching `published_snapshots` row proves successful collection and publication. `FAILED` proves failure only when failure occurred before collection validation. `INCOMPLETE` with `details.reason=superseded` proves loss of publication eligibility, **not** successful collection by itself. Pre-`0012` losers have no persisted collection-completion receipt or staged observations. A runtime count or log line cannot reconstruct their success after the process exits. Treat old superseded attempts as `UNKNOWN_LEGACY + SUPERSEDED_BEFORE_PUBLICATION` unless another durable record proves more. A historical `INCOMPLETE` with an unrecognized reason is `UNKNOWN_LEGACY` for both axes.

Migration `0012` adds an append-only per-attempt collection receipt with account, scope, attempt ID, validation version, completion timestamp, explicit pagination-complete proof in coverage, principal/grant/missing-document counts, and observation digest. Scanners commit it before attempting publication; publication rejects a missing or mismatched receipt. A receipt proves validation of a collection; it does not make the unpublished observation bodies auditable. If product or audit consumers need those bodies, stage immutable observations with a separate lifecycle. Never use a receipt alone as a published snapshot or allow a superseded run to publish later.

If collection validation fails, record `FAILED` and no success receipt. If a validated collection loses the head race, preserve `SUCCEEDED` in the receipt and mark publication `SUPERSEDED_BEFORE_PUBLICATION`; the existing combined run may remain `INCOMPLETE` for old consumers. If a database or serialization error occurs after the success receipt and before commit, record publication `REJECTED` with a reason while retaining the receipt. Define crash recovery so a run left `RUNNING` after a crash is never inferred successful. The completion receipt and publication result must be idempotent for one attempt.

Publication requires a validated receipt, current attempt head, matching account/scope, zero validation errors, and an explicit complete-for-declared-scope coverage result. Check the head inside the publication transaction. Publish snapshot, observations, pointer and legacy run completion atomically. A failed, incomplete, superseded, or rejected attempt cannot publish. Preserve the previous published snapshot and historical review bindings.

A zero-finding success has an explicit complete pagination/collection proof, validated source coverage, zero principal/grant counts, and a published snapshot. Missing coverage, a truncated page stream, or an absent run is never represented by zero grants alone.

## Evidence manifests

Phase 0 publishes only `SINGLE_SOURCE` evidence-set manifests. Each manifest binds account, scope version, published snapshot ID, observation window, source coverage, missing-reference inventory, manifest schema version, and hash. A review manifest binds that evidence set to its pinned grant, observation, policy assessment, **grant assessment**, attachment identity, policy version/hash, and rule version. Current eligibility and invalidation annotations are separate projections; neither mutates a historical manifest or AI artifact.

Canonical bytes use sorted JSON object keys, UTF-8 and SHA-256. The schema defines absent versus explicit `null`, numeric representation, UTC timestamp normalization, and array semantics. Sort set-like snapshot and evidence-reference arrays by stable IDs; preserve order for arrays where sequence is meaningful, including statements. Reject duplicate IDs and duplicate JSON object keys before hashing. Test Unicode, missing/null, reordered set-like arrays, ordered statements, and equivalent serializations against fixed expected hashes. Hash the canonical manifest body without mutable eligibility annotations.

Multi-source manifests and cross-source claims remain disabled until a separately reviewed temporal-window comparison method and skew threshold exist. A source snapshot is never described as a live AWS transaction.

## Acceptance checks

- A completed collection that loses publication remains provably `SUCCEEDED` for **new** attempts; old ambiguous attempts remain unknown.
- Failed or partial collection and superseded publication cannot advance a source pointer.
- Zero-finding success is distinguishable from absent or partial coverage.
- Same-source races and crash/retry paths preserve the prior publication.
- Historical manifests, review pins, assessments, and AI artifacts stay immutable; invalidation is additive.
- SQLite and PostgreSQL agree on lifecycle behavior, including concurrent attempts.
