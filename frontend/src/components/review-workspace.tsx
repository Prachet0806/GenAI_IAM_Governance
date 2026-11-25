"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, apiFetch } from "@/lib/api/client";
import { ConfirmDialog, displayDate, pretty } from "@/components/workspace-ui";
import type { AiExplanation, AiJob, ReviewAssessment, ReviewDetail, ReviewHistoryEvent, ReviewQuestionAnswer } from "@/lib/api/types";

function EvidenceItem({ label, value }: { label: string; value: React.ReactNode }) { return <div className="evidence-item"><dt>{label}</dt><dd>{value || "Not recorded"}</dd></div>; }

export function ReviewWorkspace({ reviewId }: { reviewId: string }) {
  const client = useQueryClient();
  const [comment, setComment] = useState("");
  const [aiJobId, setAiJobId] = useState<string | null>(null);
  const [pendingDecision, setPendingDecision] = useState<"APPROVED" | "REVOKED" | null>(null);
  const [decisionNotice, setDecisionNotice] = useState("");
  const detail = useQuery({ queryKey: ["review", reviewId], queryFn: () => apiFetch<ReviewDetail>(`reviews/${encodeURIComponent(reviewId)}`) });
  const history = useQuery({ queryKey: ["history", reviewId], queryFn: () => apiFetch<{ events: ReviewHistoryEvent[] }>(`reviews/${encodeURIComponent(reviewId)}/history?limit=100&offset=0`) });
  const decision = useMutation({ mutationFn: (value: "APPROVED" | "REVOKED") => apiFetch<{ status: string }>(`reviews/${encodeURIComponent(reviewId)}/decision`, { method: "POST", body: JSON.stringify({ decision: value, comment }) }), onSuccess: async (_result, value) => { setPendingDecision(null); setDecisionNotice(`${pretty(value)} decision recorded in the review history.`); await Promise.all([client.invalidateQueries({ queryKey: ["review", reviewId] }), client.invalidateQueries({ queryKey: ["history", reviewId] }), client.invalidateQueries({ queryKey: ["queue"] }), client.invalidateQueries({ queryKey: ["summary"] })]); }, onError: () => setPendingDecision(null) });
  const explanation = useMutation({ mutationFn: () => apiFetch<{ job_id: string }>(`reviews/${encodeURIComponent(reviewId)}/ai/explanation`, { method: "POST" }), onSuccess: (job) => setAiJobId(job.job_id) });
  const question = useMutation({ mutationFn: (intent: string) => apiFetch<ReviewQuestionAnswer>(`reviews/${encodeURIComponent(reviewId)}/ai/questions`, { method: "POST", body: JSON.stringify({ intent }) }) });
  const aiJob = useQuery({
    queryKey: ["ai-job", aiJobId],
    queryFn: () => apiFetch<AiJob>(`ai/jobs/${encodeURIComponent(aiJobId!)}`),
    enabled: Boolean(aiJobId),
    refetchInterval: (query) => ["PENDING", "RUNNING"].includes(query.state.data?.status ?? "") ? 2000 : false,
  });
  const explainError = explanation.error instanceof Error ? explanation.error.message : "An explanation could not be requested.";
  const decisionReady = detail.data?.status === "PENDING" && detail.data.campaign_state === "OPEN" && detail.data.exception_state !== "OPEN";
  const current = detail.data?.snapshot_current_eligible;
  const timeline = useMemo(() => [...(history.data?.events ?? [])].reverse(), [history.data]);

  useEffect(() => {
    if (aiJob.data && !["PENDING", "RUNNING"].includes(aiJob.data.status)) {
      void client.invalidateQueries({ queryKey: ["review", reviewId] });
    }
  }, [aiJob.data, client, reviewId]);

  if (detail.isLoading) return <div className="loading" role="status">Loading review evidence…</div>;
  if (detail.isError || !detail.data) return <div className="error" role="alert"><Link className="row-link" href="/reviews">← Back to queue</Link><p>{detail.error instanceof Error ? detail.error.message : "This review could not be loaded."}</p><button className="button" onClick={() => void detail.refetch()}>Try again</button></div>;

  const item = detail.data;
  const assessment = item.assessment;
  const path = item.observed_path;
  const invalidations = item.evidence_invalidations ?? [];
  const riskTitle = assessment
    ? assessment.risk_severity === "UNKNOWN"
      || (assessment.assessment_status !== "SUPPORTED"
        && assessment.risk_severity === "LOW")
      ? "Assessment incomplete"
      : `${pretty(assessment.risk_severity)} pattern`
    : `${pretty(item.risk_level)} legacy triage`;
  const canActAsReviewer = item.can_decide;
  const decisionBlockMessages: Record<string, string> = {
    REVIEWER_GROUP_REQUIRED: "Your account is not in the configured reviewer group.",
    CAMPAIGN_MEMBERSHIP_REQUIRED: "You are not assigned to this campaign's reviewer pool.",
    ASSIGNED_TO_ANOTHER_REVIEWER: "This review is assigned to another reviewer.",
    REVIEW_ALREADY_DECIDED: "A decision has already been recorded for this review.",
    CAMPAIGN_NOT_OPEN: `This campaign is ${pretty(item.campaign_state).toLowerCase()}.`,
    OPEN_EXCEPTION: "An open exception is blocking decisions. Ask the campaign administrator to resolve it.",
    EVIDENCE_NOT_CURRENT: "The evidence snapshot is no longer current. Ask the campaign administrator to refresh it.",
  };
  const ai = item.ai_explanation as AiExplanation | undefined;
  const generalError = decision.error instanceof Error ? decision.error.message : "Your decision could not be recorded.";
  return <>
    <div className="breadcrumb-link"><Link className="row-link" href="/reviews">← My review queue</Link></div>
    <div className="page-heading detail-heading"><div><div className="eyebrow">Access certification · {item.review_id}</div><h1>{item.user}</h1><p className="subhead">Review the observed grant, its source and recorded risk evidence.</p></div><span className={`badge ${assessment?.risk_severity === "CRITICAL" ? "high" : (assessment?.risk_severity ?? item.risk_level).toLowerCase()}`}>{riskTitle}</span></div>
    {item.review_scope === "LEGACY_UNKNOWN_PATH" && <div className="notice warning" role="status"><strong>Grant path not fully identified.</strong> This legacy review does not contain a verifiable grant-path binding. A decision here does not establish that the principal has or has lost all effective access.</div>}
    {item.review_scope === "GRANT_PATH" && <div className="notice" role="note"><strong>This decision applies to one observed grant path.</strong> The system has not evaluated whether the principal has equivalent access through other paths.</div>}
    {current === false && item.review_scope === "GRANT_PATH" && <div className="notice danger" role="alert"><strong>Evidence is no longer current.</strong> The source snapshot is no longer the eligible published snapshot. Refresh evidence through your administrator before making a decision.</div>}
    {invalidations.length > 0 && <div className="notice danger" role="alert"><strong>Pinned evidence was invalidated.</strong> {invalidations.map((entry) => entry.detail).join("; ")} A new scan and review are required; this historical record remains visible.</div>}
    {assessment && (assessment.assessment_status !== "SUPPORTED" || assessment.evidence_completeness.document_coverage !== "COMPLETE") && <div className="notice warning" role="status"><strong>Assessment incomplete.</strong> Some policy evidence or constructs could not be evaluated. Investigate the missing evidence and limitations before deciding.</div>}
    {decisionNotice && <div className="notice" role="status">{decisionNotice} <a className="row-link" href="#decision-history">View recorded history</a> · <Link className="row-link" href="/reviews">Continue to queue</Link></div>}
    {decision.isError && <div className="error" role="alert">{generalError} <span className="mono">{decision.error instanceof ApiError ? `Request ${decision.error.requestId ?? "ID unavailable"}` : ""}</span></div>}
    <div className="detail-grid">
      <div className="stack">
        <section className="panel"><div className="panel-head"><div><h2>Observed access</h2><div className="secondary">Grant-path evidence captured for this campaign</div></div><span className={`badge ${item.status.toLowerCase()}`}>{pretty(item.status)}</span></div><div className="panel-body">{path && <ol className="grant-path" aria-label="Observed grant path"><li><span>Principal</span><strong>{path.principal_name}</strong><small className="mono">{path.principal_arn}</small></li><li><span>{path.grant_type.startsWith("GROUP_") ? "Group source" : "Observed source"}</span><strong>{path.source_name}</strong><small>{pretty(path.grant_type)} · {path.source_id}</small></li><li><span>Policy attachment</span><strong>{path.policy_name}</strong><small className="mono">{path.attachment_id}</small></li><li><span>Frozen version</span><strong>{path.policy_version || "No version recorded"}</strong><small className="mono">{path.policy_sha256}</small></li></ol>}<dl className="evidence-list">
          <EvidenceItem label="Principal" value={item.user} /><EvidenceItem label="Grant or entitlement" value={item.entitlement} />
          <EvidenceItem label="Grant type" value={pretty(item.grant_type)} /><EvidenceItem label="Grant source" value={pretty(item.grant_source)} />
          <EvidenceItem label="AWS account" value={item.source_account_id} /><EvidenceItem label="Source scope" value={pretty(item.source_scope)} />
          <EvidenceItem label="Campaign snapshot" value={<span className="mono">{item.snapshot_id || "Not recorded"}</span>} /><EvidenceItem label="Observed at" value={path?.observed_at ? displayDate(path.observed_at) : "Not recorded"}/><EvidenceItem label="Collection completed" value={path?.collected_at ? displayDate(path.collected_at) : "Legacy timestamp unavailable"}/><EvidenceItem label="Snapshot published" value={item.snapshot_published_at ? displayDate(item.snapshot_published_at) : "Not recorded"} />
          <EvidenceItem label="Grant ID" value={<span className="mono">{item.grant_id || "Not recorded"}</span>} /><EvidenceItem label="Observation ID" value={<span className="mono">{item.observation_id || "Not recorded"}</span>} />
          <EvidenceItem label="Risk assessment" value={<span className="mono">{item.risk_assessment_id || "Not recorded"}</span>} /><EvidenceItem label="Effective access" value="Not evaluated" />
        </dl></div></section>
        <section className="panel"><div className="panel-head"><div><h2>Risk assessment</h2><div className="secondary">Rule-based assessment linked to this grant observation</div></div></div><div className="panel-body">
          <div className={`risk-callout ${assessment?.risk_severity === "CRITICAL" || assessment?.risk_severity === "HIGH" ? "high" : ""}`}><strong>{riskTitle}</strong><div>{assessment ? assessment.reason_codes.map(pretty).join("; ") || "No supported pattern was identified." : item.risk_reason || "No narrative risk reason was recorded."}</div></div>
          {assessment && <dl className="evidence-list risk-meta"><EvidenceItem label="Assessment" value={pretty(assessment.assessment_status)} /><EvidenceItem label="Confidence in document triage" value={pretty(assessment.assessment_confidence)} /><EvidenceItem label="Declared source scope" value={pretty(assessment.evidence_completeness.source_coverage)} /><EvidenceItem label="Policy document coverage" value={pretty(assessment.evidence_completeness.document_coverage)} /><EvidenceItem label="Manual review" value={assessment.manual_review_required ? "Required" : "Not required by these rules"} /></dl>}
          {assessment?.evidence_completeness.unassessed_surfaces?.length ? <div className="notice warning">Other IAM surfaces were not evaluated: {assessment.evidence_completeness.unassessed_surfaces.map(pretty).join(", ")}.</div> : null}
          <dl className="evidence-list risk-meta"><EvidenceItem label="Risk rule version" value={item.risk_rule_version} /><EvidenceItem label="Policy version" value={item.policy_version} /><EvidenceItem label="Policy SHA-256" value={<span className="mono">{item.policy_sha256}</span>} /><EvidenceItem label="Policy evidence" value={pretty(item.policy_evidence_status)} /></dl>
          {item.missing_policy_reason && <div className="notice warning">Policy evidence unavailable: {item.missing_policy_reason}</div>}
          <details className="policy-details"><summary>Exact assessment evidence</summary><div className="policy-summary"><dl className="evidence-list compact-evidence"><EvidenceItem label="Source manifest SHA-256" value={<span className="mono">{item.source_manifest_sha256}</span>} /><EvidenceItem label="Review manifest SHA-256" value={<span className="mono">{item.review_manifest_sha256}</span>} /></dl>{item.risk_evidence !== null && item.risk_evidence !== undefined && <pre className="policy">{JSON.stringify(item.risk_evidence, null, 2)}</pre>}</div></details>
          {item.policy_document && <PolicySummary policy={item.policy_document} references={assessment?.statement_refs ?? []} />}
        </div></section>
        <section className="panel"><div className="panel-head"><div><h2>AI explanation</h2><div className="secondary">Optional summary grounded in evidence; it does not make the decision.</div></div>{canActAsReviewer && <button className="button" disabled={explanation.isPending || ["PENDING", "RUNNING"].includes(aiJob.data?.status ?? "") || item.status !== "PENDING" || current === false} onClick={() => explanation.mutate()}>{explanation.isPending ? "Requesting…" : ai?.status ? "Request another explanation" : "Request explanation"}</button>}</div><div className="panel-body">
          {explanation.isError && <div className="notice warning" role="alert">{explainError}</div>}
          {aiJob.data && ["PENDING", "RUNNING"].includes(aiJob.data.status) && <div className="notice" role="status">The explanation is being prepared from the review evidence. This page will update when processing finishes.</div>}
          {aiJob.data?.status === "FAILED" && <div className="notice warning" role="status">The explanation could not be generated ({aiJob.data.last_error_code || "processing error"}). You can try again later.</div>}
          {ai?.summary ? <><div className="ai-summary">{ai.summary}</div>{ai.limitations && <div className="notice warning">Limitations: {ai.limitations}</div>}<div className="secondary">{ai.authority || "Advisory explanation"} · {ai.provider || "Configured provider"}{ai.model ? ` / ${ai.model}` : ""}{ai.generated_at ? ` · ${new Date(ai.generated_at).toLocaleString()}` : ""}</div>{ai.citations?.length ? <div className="citation-list"><strong>Evidence references</strong>{ai.citations.map((citation) => <span className="badge neutral" key={citation.id}>{pretty(citation.kind)} · {citation.id}</span>)}</div> : null}</> : <div className="secondary">{ai?.message || "No explanation is attached. You can review the source and risk evidence without requesting one."}</div>}
        </div></section>
        {item.review_qa_enabled && canActAsReviewer && item.status === "PENDING" && item.campaign_state === "OPEN" && <section className="panel"><div className="panel-head"><div><h2>Ask about this review</h2><div className="secondary">Answers use templates checked against this review&apos;s pinned evidence.</div></div></div><div className="panel-body"><div className="decision-actions">{([ ["ATTACHMENT", "How was this policy attached?"], ["RULE", "What did the rule detect?"], ["LIMITATIONS", "What is unknown?"], ["NEXT_EVIDENCE", "What should I inspect?" ]] as const).map(([intent, label]) => <button className="button" key={intent} disabled={question.isPending} onClick={() => question.mutate(intent)}>{label}</button>)}</div>{question.isError && <div className="notice warning" role="alert">{question.error instanceof Error ? question.error.message : "The question could not be answered."}</div>}{question.data && <div role="status"><p>{question.data.answer}</p><p className="secondary">{question.data.limitations}</p>{question.data.current_snapshot_eligible === false && <div className="notice warning">This pinned snapshot is no longer current or eligible for decisions.</div>}<div className="citation-list"><strong>Pinned evidence</strong>{question.data.evidence.cited.map((id) => <span className="badge neutral mono" key={id}>{id}</span>)}</div></div>}</div></section>}
        <section className="panel" id="decision-history"><div className="panel-head"><div><h2>Decision history</h2><div className="secondary">Recorded decisions and workflow events</div></div></div><div className="panel-body">{history.isError && <div className="error" role="alert">History could not be loaded. <button className="button" onClick={() => void history.refetch()}>Retry</button></div>}{timeline.length ? <div className="timeline">{timeline.map((event) => <div className="timeline-item" key={event.event_id}><span className="timeline-dot" aria-hidden="true"/><div><div className="timeline-title">{pretty(event.decision || event.event_type)}{event.decision_origin ? ` · ${pretty(event.decision_origin)}` : ""}</div>{event.comment && <div>{event.comment}</div>}<div className="timeline-meta">{event.actor_sub || "System"} · {displayDate(event.created_at)}</div></div></div>)}</div> : <div className="empty compact-empty">No decision or workflow events are recorded yet.</div>}</div></section>
      </div>
      <aside className="stack decision-panel">
        <section className="panel"><div className="panel-head"><div><h2>Your decision</h2><div className="secondary">{decisionReady ? "Choose the outcome for this observed grant." : "This review is not open for decisions."}</div></div></div><div className="panel-body">
          {item.exception_state === "OPEN" && <div className="notice warning">An open exception is blocking decisions. Ask the campaign administrator to resolve it.</div>}
          {item.campaign_state !== "OPEN" && <div className="notice warning">This campaign is {pretty(item.campaign_state).toLowerCase()}.</div>}
          {item.status !== "PENDING" && <div className="notice">A decision has already been recorded for this review.</div>}
          {decisionReady && canActAsReviewer && <><div className="field"><label htmlFor="comment">Reviewer comment {item.status === "PENDING" ? <span className="optional">(required for revocation)</span> : null}</label><textarea id="comment" className="textarea" maxLength={4000} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Record the reason for your decision. A comment is required to revoke." /></div><div className="decision-actions"><button className="button primary" disabled={decision.isPending || current === false} onClick={() => setPendingDecision("APPROVED")}>Approve grant path</button><button className="button danger" disabled={decision.isPending || current === false || !comment.trim()} onClick={() => setPendingDecision("REVOKED")}>Revoke grant path</button></div>{current === false && <p className="secondary">Decisions are disabled because this snapshot is no longer current.</p>}<p className="decision-disclaimer">Your action is recorded in the certification history. Revoking this path does not prove that all access has been removed.</p></>}
          {decisionReady && !canActAsReviewer && <div className="notice">Read-only evidence view. {decisionBlockMessages[item.can_decide_reason ?? ""] ?? "The API reports that this review is not eligible for your decision."}</div>}
        </div></section>
        <section className="panel"><div className="panel-head"><h2>Review context</h2></div><div className="panel-body"><dl className="context-list"><EvidenceItem label="Assignment" value={item.assigned_reviewer_sub || "Campaign reviewer"} /><EvidenceItem label="Due date" value={item.due_at ? new Date(item.due_at).toLocaleString() : "No deadline"} /><EvidenceItem label="Evidence state" value={pretty(item.evidence_state)} /><EvidenceItem label="Source coverage" value={item.source_coverage ? "Available" : "Not recorded"} /></dl></div></section>
      </aside>
    </div>
    {pendingDecision && <ConfirmDialog title={`${pendingDecision === "REVOKED" ? "Revoke" : "Approve"} this observed grant path?`} confirmLabel={pendingDecision === "REVOKED" ? "Record revocation" : "Record approval"} danger={pendingDecision === "REVOKED"} busy={decision.isPending} onCancel={() => setPendingDecision(null)} onConfirm={() => decision.mutate(pendingDecision)} summary={<><p>This exact review decision will be recorded in the certification history.</p><dl className="evidence-list compact-evidence"><EvidenceItem label="Principal" value={item.user}/><EvidenceItem label="Grant or entitlement" value={item.entitlement}/><EvidenceItem label="AWS account" value={item.source_account_id}/><EvidenceItem label="Grant ID" value={<span className="mono">{item.grant_id || "Not recorded"}</span>}/><EvidenceItem label="Snapshot" value={<span className="mono">{item.snapshot_id || "Not recorded"}</span>}/><EvidenceItem label="Reviewer comment" value={comment || "No comment"}/></dl><p className="decision-disclaimer">A revocation applies to this observed grant path only. Effective access through other paths has not been evaluated.</p></>}/>}
  </>;
}

function PolicySummary({ policy, references }: { policy: Record<string, unknown>; references: NonNullable<ReviewAssessment["statement_refs"]> }) {
  const raw = Array.isArray(policy.Statement) ? policy.Statement : policy.Statement ? [policy.Statement] : [];
  return <details className="policy-details"><summary>Inspect frozen policy statements · {raw.length} statements</summary><div className="policy-summary"><dl className="evidence-list compact-evidence"><EvidenceItem label="Policy version" value={String(policy.Version ?? "Not recorded")}/><EvidenceItem label="Statement count" value={raw.length}/></dl>{raw.length ? raw.map((value, index) => {
    const statement = value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
    const match = references.find((ref) => ref.statement_index === index);
    return <article className="policy-statement" key={index}><div className="policy-statement-heading"><strong>Statement {index + 1}{statement.Sid ? ` · ${String(statement.Sid)}` : ""}</strong><span className={`policy-effect ${String(statement.Effect ?? "").toLowerCase()}`}>{pretty(statement.Effect)}</span></div>
      {match && <div className="notice"><strong>Rule finding for this statement:</strong> {match.reason_codes.map(pretty).join("; ") || "No concerning pattern matched"}{match.matched_actions?.length ? ` · ${match.matched_actions.join(", ")}` : ""}</div>}
      <dl className="evidence-list compact-evidence"><EvidenceItem label={statement.NotAction ? "Not action" : "Actions"} value={joinPolicyValue(statement.Action ?? statement.NotAction)}/><EvidenceItem label={statement.NotResource ? "Not resource" : "Resources"} value={joinPolicyValue(statement.Resource ?? statement.NotResource)}/><EvidenceItem label={statement.NotPrincipal ? "Not principal" : "Principal"} value={statement.Principal || statement.NotPrincipal ? JSON.stringify(statement.Principal ?? statement.NotPrincipal) : "Not present"}/><EvidenceItem label="Conditions" value={statement.Condition ? JSON.stringify(statement.Condition) : "None recorded"}/></dl>
      <details className="event-details"><summary>Exact frozen statement JSON</summary><pre className="policy">{JSON.stringify(value, null, 2)}</pre></details>
    </article>;
  }) : <pre className="policy">{JSON.stringify(policy, null, 2)}</pre>}</div></details>;
}

function joinPolicyValue(value: unknown) { return Array.isArray(value) ? value.join(", ") : value == null ? "Not recorded" : String(value); }
