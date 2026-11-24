# Phase 0 IAM policy parsing and claim contract

Status: initial parser and rule implementation is local in `common/policy_assessment.py` and `policy-risk-v6`. Independent IAM scenario review and PostgreSQL/hosted acceptance remain open. The parser supports evidence-backed syntax triage; it does not evaluate a principal's effective AWS permissions.

## Input and identity

Accept the frozen observation body and its account, source scope, snapshot ID, observation ID, grant ID, source ID, attachment ID, policy type, policy version (when available), document hash and observation time. Require a valid identity chain before assessment. A managed-policy version read must match the version recorded with the document; if the default version changes between metadata and document reads, re-read coherently or mark the observation incomplete. An absent attachment identity is a collection/validation error, not a policy with LOW severity. An absent version must be labeled unavailable; never invent one.

Keep the raw or exact source document bytes when available and a canonical parsed form with an explicit parser version. If a provider returns a native object rather than raw JSON, record that duplicate-key detection at the original serialization boundary was unavailable; validate object shape and mark provenance accordingly. For textual JSON, reject duplicate object keys before ordinary dictionary parsing, including nested statement/condition objects. Reject invalid JSON. Do not silently let a later duplicate key replace an earlier one.

## Shape validation

| Input case | Required result |
| --- | --- |
| `Version=2012-10-17` | Supported for Phase 0 only when every relevant statement shape and rule is covered. |
| `Version=2008-10-17`, another version, or missing `Version` | Preserve the document and mark `UNSUPPORTED` until version-specific behavior has reviewed fixtures; no reassuring LOW. |
| Missing, empty, or malformed `Statement` | Mark `UNASSESSED` or `UNSUPPORTED` with a reason; no synthetic empty grant conclusion. |
| Statement array with mixed valid/invalid items | Assess valid items independently, retain invalid item indices, mark overall `PARTIAL`. |
| Invalid `Effect` or unexpected types in `Action`, `NotAction`, `Resource`, `NotResource`, `Principal`, `NotPrincipal`, or `Condition` | Preserve the exact construct and reason; do not coerce objects, numbers or booleans to strings. |
| Both positive and negative forms of one element | Mark unsupported/malformed under a documented rule; do not choose one silently. |
| Multiple statements with Allow, Deny and different conditions | Preserve statement order/index and each reason; do not merge into a fabricated aggregate permission. |
| Valid JSON using an unsupported IAM construct | Preserve parse success and separate `UNSUPPORTED` interpretation status. |
| Referenced policy document missing | Preserve attachment and missing-reference reason; `document_coverage` is partial/missing, independent of scan completion. |

The parser recognizes policy type before applying type-specific rules: IAM identity policy, role trust policy, and Identity Center assignment evidence. Resource policies, boundaries, SCPs, RCPs and session policies are explicitly uncollected/unevaluated until scoped support exists. `NotAction`, `NotResource`, `NotPrincipal`, conditions and explicit Deny remain exact source facts; their authorization effect is not inferred by Phase 0 string matching.

Each statement result records zero-based index, optional `Sid`, observed effect, exact recognized action/principal/resource values, unsupported constructs, document hash, and parse/rule reason codes. Public claims are typed `OBSERVED_FACT`, `RULE_INFERENCE`, `EXTERNAL_FINDING`, or `NOT_EVALUATED`. The current product emits only observed facts and rule inferences. A rule inference identifies its version and exact statement/attachment evidence. Assessment acceptance requires the complete identity chain above and a frozen policy version/hash; the grant-level binding cannot be validated by document hash alone.

Test duplicate keys, invalid JSON, unsupported versions, malformed/empty statements, unexpected types, mixed effects/conditions, changed managed-policy versions, missing attachment metadata, missing referenced documents, and valid but unsupported constructs. Expected outcomes and permitted wording require independent IAM review before P0.3 sign-off.
