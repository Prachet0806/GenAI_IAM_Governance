# IAM governance roadmap

Product promise: help an administrator collect traceable IAM relationships, an assigned reviewer decide or escalate **one observed grant path** with uncertainty visible, and an auditor reconstruct the frozen evidence and decision. AI is optional and advisory. A policy attachment does not prove effective AWS authorization or business need. The target buyer is an IAM/security team with recurring certification work; real buyer and reviewer validation is still open.

Status (local `upgrade` worktree, 2026-11-25): the deterministic Release 1 path and a default-off Release 2 implementation slice exist. Neither release has customer, managed OIDC/AWS staging, hosted-CI-at-release-revision, or production acceptance. Release 2 has no approved real-provider quality run, historical corpus, independent IAM grading, or reviewer study. The original catalogue's `CUR-01`–`CUR-26` described an older baseline; `FIN` IDs below are target outcomes, not proof of completion. The earlier v2.1 source audit was at `7a895f1` on 2026-11-21 and must be repeated at the target commit.

## Release map

| Release and catalogue scope | Customer outcome | Gate and boundary |
| --- | --- | --- |
| **1. Governance foundation**: `FIN-01`–`FIN-30`, `FIN-38` | Collect → inspect coverage/history → inspect one pinned direct or group-derived path and matched statement → decide/escalate → verify export. Works with AI off. | Independently reviewed evidence/risk corpus, correct role journeys, account authorization, SQLite/PostgreSQL, hosted CI, managed OIDC/AWS staging, and buyer observation. Same-scope snapshot comparison reports observed changes only; cross-source access inference stays unknown. |
| **2. Review assistant**: `FIN-31`–`FIN-37`, `FIN-39`–`FIN-45`; retain `FIN-38` | Grounded explanation and narrowly scoped, stateless Q&A improve correct, defensible reviews. | Explanation quality/privacy/provider/operations gate, Q&A adversarial gate, counterbalanced reviewer study, then controlled pilot. Stop if the deterministic screen is better. |
| **3. Policy intelligence**: `FIN-46`–`FIN-54` | Versioned policy diff, attributed Access Analyzer findings, and typed possible paths. | Separate evidence/time/scope contract; no invented LLM edges or exploitability claim. |
| **4. Governance analytics**: `FIN-55`–`FIN-59` | Reproducible metrics by account, period, denominator, and coverage. | Buyer need and deterministic query tests. |
| **5. Automation**: `FIN-60`–`FIN-65` | Action-specific, independently approved remediation plans. | Deterministic pre/postflight, fencing, recovery, separate live staging approval. |
| **6. Compliance assistance**: `FIN-66`–`FIN-70` | Period/control-bound evidence and draft narratives. | Framework version, exceptions, human attestation; AI does not certify. |

Releases 3–6 are separate investments, not an implementation backlog authorized by this roadmap. The catalogue's suggested Release 1 range included AI stories; this map assigns `FIN-31`–`FIN-37` to Release 2 and makes `FIN-38` (AI-independent operation) an invariant of every release.

## Foundation and Release 1 work

The dependency order was **P0.1 contract audit → P0.2 collection/publication → P0.3 deterministic risk → P0.4 API/workspace → R1.1–R1.3 product journey**. The detailed invariant is in [evidence and risk](evidence-and-risk.md); [frontend/API contract](frontend-api-contract.md) describes roles and routes.

| Package | Scope and source files | Exit evidence |
| --- | --- | --- |
| P0.1 contract audit | Inspect `common/evidence.py`, `common/repo.py`, scanners, `lambdas/risk_evaluation/handler.py`, campaign generator, API, AI consumers, exports, and migrations for old `risk_level` assumptions. | Independently reviewed claims/severity corpus and historical-row behavior at the target revision. |
| P0.2 evidence lifecycle | `common/source_scanner.py`, discovery handlers, `common/evidence_manifest.py`, `common/repo.py`, migrations `0012`/`0014`. | Complete collection proven separately from publication; failed/superseded attempts cannot publish; zero findings, crash/race, canonical hashes, and old pins tested on SQLite/PostgreSQL. |
| P0.3 risk | `common/policy_assessment.py`, risk handler, repository, grant-assessment tests. | Policy-type and statement triage retain unsupported/missing evidence; severity, confidence, completeness, and legacy routing remain distinct; exact attachment/version binding. |
| P0.4 and R1.1 scan history | `common/workspaces.py`, API, `frontend/src/components/workspace-pages.tsx`, API types/schema/allowlist. | Administrator can explain collection versus publication, coverage, observation time, eligibility/invalidation, and bounded same-account/scope snapshot changes. |
| R1.2 reviewer path | `common/repo.py`, API, `frontend/src/components/review-workspace.tsx`, types/schema, API/UI/browser tests. | Reviewer traces principal → source relationship → attachment → frozen version/statement/rule, sees missing/stale evidence, and records an authorized decision or escalation. |
| R1.3 auditor reconstruction | `reports/export_audit.py`, `common/workspaces.py`, API, auditor UI, export tests. | Auditor independently reconstructs source/review manifests, grant, assessment, decision, invalidation, and verified CSV/JSON/evidence/manifest artifacts; old proof gaps are labelled. |

Local migrations `0012`–`0014`, `policy-risk-v6`, the API/UI, and audit exports implement these paths. That is implementation evidence. A complete scan covers only its declared source; role and Identity Center scopes publish separately. Old reviews remain readable without invented evidence. Confidence describes the rule conclusion, not a probability of AWS authorization. A newer failed attempt does not erase prior publication, but blocks new eligibility. Test AI-off direct, group, missing, stale, invalidated, empty and legacy cases. Release 1 acceptance additionally needs a real administrator, reviewer, and auditor completing this journey in managed staging, account isolation, independent corpus review, PostgreSQL and hosted CI at the exact commit, accessibility checks, and evidence of recurring buyer value. [Product validation](product-validation.md) defines the observation protocol.

## Release 2 work and decision

Phase 1 evaluates the existing `REVIEW_EXPLANATION` task for factual support, privacy, citation completeness, limitations, operational reliability, reviewer utility, and cost. The local v5 worker now minimizes provider input, requires exact versioned approval, fences retired prompts, and records additive provenance (`0015`). `scripts/build_ai_eval_candidates.py`, `scripts/run_ai_eval_candidates.py`, and `scripts/evaluate_ai_explanations.py` support a guarded run and offline screen. Their synthetic cases remain unreviewed. See [AI governance](ai-governance.md) for the payload, artifacts, threat model, corpus sizes, grades, budgets, and release gate.

Phase 2 is a conditional narrow Q&A implementation in `common/ai/retrieval.py`, `validation.py`, and `review_qa.py`, with API route, frontend, and tests. It uses the pinned review manifest, exact structured claims, templates, per-turn authorization, abstention, and redacted telemetry. It has no model-backed conversation, durable Q&A task, or policy-document provider input. Unsupported effective-access, safe-replacement, equivalent-path, cross-account, and impact questions abstain. Its feature flag remains off until Phase 1 and product discovery justify pilot use.

Phase 3 compares realistic review bundles using the deterministic UI versus UI plus explanation/Q&A, counterbalanced across reviewers. Measure correct path/principal/source identification, uncertainty, escalation, corrections, time per **correct** review, adoption, provider cost, and buyer response. Only adjudicate approve/revoke quality when business need is independently known. Predeclare useful improvement, stop conditions, effect size, variance, and power; record a go/no-go decision. Faster wrong answers fail. [Product validation](product-validation.md) contains the pilot protocol.

## Later investments and change discipline

| Proposal | Likely files | Required new proof |
| --- | --- | --- |
| Policy diff and Access Analyzer evidence | `common/evidence.py`, `common/repo.py`, API, review UI; optional `common/policy/diff.py` | Exact document versions, external finding scope/time/limits/cost, no safe-replacement claim. |
| Candidate attack paths | Scanners, evidence/repo/API; optional `common/attack_paths/` | Typed observed/possible/validated/unknown edges, request context and temporal consistency; no LLM-created edges. |
| Analytics | `common/workspaces.py`, repo/API, campaign UI; optional `common/analytics/` | Versioned numerator/denominator, scope, period and coverage; reproducible queries. |
| Remediation plans | Existing remediation handler, repo/workflow/API/export/approval UI; optional `common/remediation_plans/` | Action-specific deterministic check, independent approval, intent/fencing/postflight/recovery, live staging acceptance. |
| Compliance drafts | Export/repo/API/auditor UI; optional `common/compliance/` | Named framework/version/control/period, exceptions, retention, and human sign-off. |

For any change, recheck branch/commit and migration head. Applied migrations are immutable: add the next ordered file, define old-row behavior and read-old/write-new rollout, test SQLite/PostgreSQL parity and in-flight jobs. New routes need API account/role checks, BFF allowlist, OpenAPI/type regeneration, UI and security tests. New AI artifacts need frozen evidence/output hashes, model/prompt/schema/rule versions, approval provenance, validation, fallback/error, usage, and legacy labels. Capture local checks, hosted CI, real OIDC/AWS/provider results, and release sign-off **separately** at the same revision. Never let an AI-disabled failure block deterministic review and audit.
