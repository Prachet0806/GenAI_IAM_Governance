# Phase 0 deterministic risk assessment contract

Status: implemented locally in `policy-risk-v6` for the listed rules; independent IAM corpus review and PostgreSQL/hosted acceptance remain open. Historical `policy-risk-v5` assessments are unchanged.

## Payload and compatibility

The document-level result lives in immutable `policy_risk_assessments.evidence`. Migration `0013` adds nullable `grant_risk_assessments.evidence` for attachment identity and completeness that vary by observation. Keep legacy `risk_level` as the workflow routing field until every consumer is migrated. New code maps `UNKNOWN` severity or incomplete evidence to legacy `HIGH` for safe routing while exposing the structured reason. Old assessments remain labeled legacy/unknown; do not derive confidence from an old HIGH.

| Field | Values and rule |
| --- | --- |
| `schema_version`, `rule_version` | Required on new payloads; never overwrite an old assessment. |
| `risk_severity` | `CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN`; document-pattern triage, never effective-access severity. |
| `assessment_status` | `SUPPORTED/PARTIAL/UNASSESSED/UNSUPPORTED`; how much the parser and rules handled. |
| `assessment_confidence` | `HIGH/MEDIUM/LOW/INSUFFICIENT`; confidence in the documented triage result, not an authorization probability. |
| `evidence_completeness` | Structured collection, source, document and interpretability fields below. |
| `manual_review_required`, `reason_codes[]` | Independent of severity; retain all matched and unresolved reasons. |
| `statement_refs[]` | Statement index/Sid, exact frozen document hash, observed attachment/grant identity, policy version if available, matched action/construct. |

`evidence_completeness` must contain `collection_status` (`COMPLETE/PARTIAL/FAILED/UNKNOWN`), `source_coverage` (`COMPLETE/PARTIAL/UNKNOWN`), `document_coverage` (`COMPLETE/PARTIAL/MISSING/UNKNOWN`), `interpretability` (`SUPPORTED/PARTIAL/UNSUPPORTED/UNASSESSED`), `missing_evidence_count`, `unsupported_constructs[]`, and `reason_codes[]`. Counts are nonnegative and reconciled to the source snapshot. `COMPLETE` collection with zero observations is valid only with the explicit zero-finding proof in [the lifecycle contract](evidence-lifecycle.md). A missing referenced document is `document_coverage=PARTIAL` or `MISSING` even when the source scan itself completed. Do not collapse source coverage and parser support into one flag.

`source_coverage=COMPLETE` covers only the declared source scope. The grant-level payload also lists `unassessed_surfaces[]` so omitted IAM surfaces cannot be read as full effective-permission coverage.

## Severity decision table

Rules evaluate **each statement** and retain every reason. The maximum supported concern sets severity; unknown/unsupported evidence adds manual review without erasing a known concern. Conditions and resource scope do not automatically lower syntactic severity. This table is the initial triage proposal to review against an independently labeled corpus before P0.3 code.

| Policy type and observed pattern | Severity | Status/confidence ceiling | Manual review |
| --- | --- | --- | --- |
| Identity policy, `Allow Action="*" Resource="*"` with no restricting construct | `CRITICAL` | `SUPPORTED/HIGH` for the pattern only | Yes, to investigate actual exposure |
| Identity policy, `Allow iam:*`, another wildcard action, or a recognized sensitive exact action (`iam:PassRole`, `sts:AssumeRole`, secret retrieval, decrypt, policy mutation) | `HIGH` | `SUPPORTED/HIGH` for exact reviewed syntax; `PARTIAL/MEDIUM` when resource/condition semantics are unassessed | Yes |
| Identity policy, exact recognized mutating action or reviewed read action with `Resource="*"`, without a higher pattern | `MEDIUM` | `SUPPORTED/HIGH` only when action and statement shape are supported; otherwise `PARTIAL/MEDIUM` | According to unresolved evidence |
| Identity policy, exact reviewed read-only action with no unsupported constructs and complete document evidence | `LOW` | `SUPPORTED/HIGH` for the narrow document-pattern conclusion | No, unless source coverage is partial |
| Role trust policy, wildcard `Principal` in an `Allow` assume-role statement | `HIGH` | `SUPPORTED/HIGH` for observed broad trust syntax; `PARTIAL/MEDIUM` if conditions/other constructs are unevaluated | Yes |
| Role trust policy, specific external principal in an `Allow` assume-role statement | `HIGH` | `SUPPORTED/HIGH` for observed external reference only | Yes |
| Role trust policy, specific same-account principal with supported shape | `MEDIUM` | `SUPPORTED/HIGH` for observed trust syntax only | According to unresolved evidence |
| Identity Center assignment with a missing/unresolved permission-set document | `UNKNOWN` unless a known concerning pattern is also present | `PARTIAL/INSUFFICIENT` for the missing portion | Yes |
| Any type: absent/invalid document, unsupported policy version, unknown action, malformed statement, or unsupported policy type with no known concerning pattern | `UNKNOWN` | `UNASSESSED` or `UNSUPPORTED/INSUFFICIENT` | Yes |
| Any type: a known HIGH pattern plus `NotAction`, `NotResource`, condition, or malformed sibling statement | `HIGH` remains | `PARTIAL/MEDIUM` or lower for the overall assessment | Yes |
| Deny-only document or no analyzable `Allow` statement | `UNKNOWN` unless a supported rule establishes a pattern | `PARTIAL` or `UNASSESSED/INSUFFICIENT` | Yes |

`iam:*` stays HIGH even with a resource string that appears narrow: the Phase 0 parser does not validate per-action resource support or a concrete request context. `Action="*"` with a constrained resource remains HIGH with `PARTIAL/MEDIUM` assessment. A trust wildcard is HIGH for broad trust syntax, not the same claim as wildcard identity actions. `CRITICAL` is reserved for the exact broad identity-policy pattern above; expand only with reviewed cases. Sensitive-action lists and the read-only allowlist are versioned rule data in `common/policy_assessment.py`. Unknown actions or unsupported siblings block a reassuring LOW result.

## Confidence and aggregation

- `HIGH` confidence requires a validated frozen document, recognized policy type, supported statement shape, exact rule match, and complete relevant document evidence.
- `MEDIUM` confidence permits a directly observed pattern with an unresolved condition, resource constraint, or separate unsupported statement; the output names the limitation.
- `LOW` confidence is reserved for a weak but still traceable pattern with material unresolved context; it cannot authorize a reassuring LOW severity.
- `INSUFFICIENT` applies when the claimed conclusion lacks enough supported evidence, including missing documents and unknown actions with no other supported pattern.

`assessment_status=SUPPORTED` requires all relevant statements to have a supported parse/rule outcome. `PARTIAL` retains supported reasons alongside unsupported ones. `UNASSESSED` means no assessment attempted or no readable document. `UNSUPPORTED` means readable input outside the current parser/rule contract. A missing source surface can lower completeness without changing a supported document-pattern reason. Explicit Deny is recorded but never subtracted from Allow using string matching. Tie-breaking is deterministic and affects display order only; preserve all reasons.

For a policy-level assessment shared by identical policy hash/rule version, preserve the policy-level conclusion. Every **grant-level** assessment reference must additionally bind its own observation ID, grant ID, attachment ID, source ID, policy version, policy hash, and snapshot ID; reject a mismatch before review/AI use. A policy hash alone cannot prove which attachment was observed. Test old API consumers, old pinned records, and SQLite/PostgreSQL parity before changing routing or display.
