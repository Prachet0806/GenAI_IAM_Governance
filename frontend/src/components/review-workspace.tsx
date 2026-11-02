"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api/client";
import type { AiExplanation, AiJob, AppIdentity, ReviewDetail, ReviewHistoryEvent } from "@/lib/api/types";

function pretty(value?: string | null) { return value ? value.toLowerCase().replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()) : "Not recorded"; }
function EvidenceItem({ label, value }: { label: string; value: React.ReactNode }) { return <div className="evidence-item"><dt>{label}</dt><dd>{value || "Not recorded"}</dd></div>; }

export function ReviewWorkspace({ reviewId }: { reviewId: string }) {
  const client = useQueryClient();
  const [comment, setComment] = useState("");
  const [aiJobId, setAiJobId] = useState<string | null>(null);
  const identity = useQuery({ queryKey: ["me"], queryFn: () => apiFetch<AppIdentity>("me") });
  const detail = useQuery({ queryKey: ["review", reviewId], queryFn: () => apiFetch<ReviewDetail>(`reviews/${encodeURIComponent(reviewId)}`) });
  const history = useQuery({ queryKey: ["history", reviewId], queryFn: () => apiFetch<{ events: ReviewHistoryEvent[] }>(`reviews/${encodeURIComponent(reviewId)}/history?limit=100&offset=0`) });
  const decision = useMutation({ mutationFn: (value: "APPROVED" | "REVOKED") => apiFetch<{ status: string }>(`reviews/${encodeURIComponent(reviewId)}/decision`, { method: "POST", body: JSON.stringify({ decision: value, comment }) }), onSuccess: async () => { await Promise.all([client.invalidateQueries({ queryKey: ["review", reviewId] }), client.invalidateQueries({ queryKey: ["history", reviewId] }), client.invalidateQueries({ queryKey: ["queue"] }), client.invalidateQueries({ queryKey: ["summary"] })]); } });
  const explanation = useMutation({ mutationFn: () => apiFetch<{ job_id: string }>(`reviews/${encodeURIComponent(reviewId)}/ai/explanation`, { method: "POST" }), onSuccess: (job) => setAiJobId(job.job_id) });
  const aiJob = useQuery({
    queryKey: ["ai-job", aiJobId],
    queryFn: () => apiFetch<AiJob>(`ai/jobs/${encodeURIComponent(aiJobId!)}`),
    enabled: Boolean(aiJobId),
    refetchInterval: (query) => ["PENDING", "RUNNING"].includes(query.state.data?.status ?? "") ? 2000 : false,
  });
  const explainError = explanation.error instanceof Error ? explanation.error.message : "An explanation could not be requested.";
  const decisionReady = detail.data?.status === "PENDING" && detail.data.campaign_state === "OPEN" && detail.data.exception_state !== "OPEN";
  const canActAsReviewer = Boolean(identity.data?.roles.includes("reviewer") && detail.data?.assigned_reviewer_sub === identity.data.subject);
  const current = detail.data?.snapshot_current_eligible;
  const timeline = useMemo(() => [...(history.data?.events ?? [])].reverse(), [history.data]);

  useEffect(() => {
    if (aiJob.data && !["PENDING", "RUNNING"].includes(aiJob.data.status)) {
      void client.invalidateQueries({ queryKey: ["review", reviewId] });
    }
  }, [aiJob.data, client, reviewId]);

  function decide(value: "APPROVED" | "REVOKED") {
    const prompt = value === "REVOKED" ? "Record a revocation for this observed grant path? This decision will be added to the certification history." : "Approve this observed grant path? This decision will be added to the certification history.";
    if (window.confirm(prompt)) decision.mutate(value);
  }

  if (detail.isLoading) return <div className="loading" role="status">Loading review evidence…</div>;
  if (detail.isError || !detail.data) return <div className="error" role="alert"><Link className="row-link" href="/reviews">← Back to queue</Link><p>{detail.error instanceof Error ? detail.error.message : "This review could not be loaded."}</p><button className="button" onClick={() => void detail.refetch()}>Try again</button></div>;

  const item = detail.data;
  const ai = item.ai_explanation as AiExplanation | undefined;
  const policy = item.policy_document ? JSON.stringify(item.policy_document, null, 2) : null;
  const generalError = decision.error instanceof Error ? decision.error.message : "Your decision could not be recorded.";
  return <>
    <div className="breadcrumb-link"><Link className="row-link" href="/reviews">← My review queue</Link></div>
    <div className="page-heading detail-heading"><div><div className="eyebrow">Access certification · {item.review_id}</div><h1>{item.user}</h1><p className="subhead">Review the observed grant, its source and recorded risk evidence.</p></div><span className={`badge ${item.risk_level.toLowerCase()}`}>{pretty(item.risk_level)} risk</span></div>
    {item.review_scope === "LEGACY_UNKNOWN_PATH" && <div className="notice warning" role="status"><strong>Grant path not fully identified.</strong> This legacy review does not contain a verifiable grant-path binding. A decision here does not establish that the principal has or has lost all effective access.</div>}
    {item.review_scope === "GRANT_PATH" && <div className="notice" role="note"><strong>This decision applies to one observed grant path.</strong> The system has not evaluated whether the principal has equivalent access through other paths.</div>}
    {current === false && item.review_scope === "GRANT_PATH" && <div className="notice danger" role="alert"><strong>Evidence is no longer current.</strong> The source snapshot is no longer the eligible published snapshot. Refresh evidence through your administrator before making a decision.</div>}
    {decision.isError && <div className="error" role="alert">{generalError} <span className="mono">{decision.error instanceof ApiError ? `Request ${decision.error.requestId ?? "ID unavailable"}` : ""}</span></div>}
    <div className="detail-grid">
      <div className="stack">
        <section className="panel"><div className="panel-head"><div><h2>Observed access</h2><div className="secondary">Grant-path evidence captured for this campaign</div></div><span className={`badge ${item.status.toLowerCase()}`}>{pretty(item.status)}</span></div><div className="panel-body"><dl className="evidence-list">
          <EvidenceItem label="Principal" value={item.user} /><EvidenceItem label="Grant or entitlement" value={item.entitlement} />
          <EvidenceItem label="Grant type" value={pretty(item.grant_type)} /><EvidenceItem label="Grant source" value={pretty(item.grant_source)} />
          <EvidenceItem label="AWS account" value={item.source_account_id} /><EvidenceItem label="Source scope" value={pretty(item.source_scope)} />
          <EvidenceItem label="Campaign snapshot" value={<span className="mono">{item.snapshot_id || "Not recorded"}</span>} /><EvidenceItem label="Snapshot published" value={item.snapshot_published_at ? new Date(item.snapshot_published_at).toLocaleString() : "Not recorded"} />
          <EvidenceItem label="Grant ID" value={<span className="mono">{item.grant_id || "Not recorded"}</span>} /><EvidenceItem label="Observation ID" value={<span className="mono">{item.observation_id || "Not recorded"}</span>} />
          <EvidenceItem label="Risk assessment" value={<span className="mono">{item.risk_assessment_id || "Not recorded"}</span>} /><EvidenceItem label="Effective access" value="Not evaluated" />
        </dl></div></section>
        <section className="panel"><div className="panel-head"><div><h2>Risk assessment</h2><div className="secondary">Rule-based assessment linked to this grant observation</div></div></div><div className="panel-body">
          <div className={`risk-callout ${item.risk_level === "HIGH" ? "high" : ""}`}><strong>{pretty(item.risk_level)} risk</strong><div>{item.risk_reason || "No narrative risk reason was recorded."}</div></div>
          <dl className="evidence-list risk-meta"><EvidenceItem label="Risk rule version" value={item.risk_rule_version} /><EvidenceItem label="Policy version" value={item.policy_version} /><EvidenceItem label="Policy SHA-256" value={<span className="mono">{item.policy_sha256}</span>} /><EvidenceItem label="Policy evidence" value={pretty(item.policy_evidence_status)} /></dl>
          {item.missing_policy_reason && <div className="notice warning">Policy evidence unavailable: {item.missing_policy_reason}</div>}
          {item.risk_evidence !== null && item.risk_evidence !== undefined && <><h3 className="section-subtitle">Risk evidence</h3><pre className="policy">{JSON.stringify(item.risk_evidence, null, 2)}</pre></>}
          {policy && <details className="policy-details"><summary>View policy document</summary><pre className="policy">{policy}</pre></details>}
        </div></section>
        <section className="panel"><div className="panel-head"><div><h2>AI explanation</h2><div className="secondary">Optional summary grounded in evidence; it does not make the decision.</div></div>{canActAsReviewer && <button className="button" disabled={explanation.isPending || ["PENDING", "RUNNING"].includes(aiJob.data?.status ?? "") || item.status !== "PENDING" || current === false} onClick={() => explanation.mutate()}>{explanation.isPending ? "Requesting…" : ai?.status ? "Request another explanation" : "Request explanation"}</button>}</div><div className="panel-body">
          {explanation.isError && <div className="notice warning" role="alert">{explainError}</div>}
          {aiJob.data && ["PENDING", "RUNNING"].includes(aiJob.data.status) && <div className="notice" role="status">The explanation is being prepared from the review evidence. This page will update when processing finishes.</div>}
          {aiJob.data?.status === "FAILED" && <div className="notice warning" role="status">The explanation could not be generated ({aiJob.data.last_error_code || "processing error"}). You can try again later.</div>}
          {ai?.summary ? <><div className="ai-summary">{ai.summary}</div>{ai.limitations && <div className="notice warning">Limitations: {ai.limitations}</div>}<div className="secondary">{ai.authority || "Advisory explanation"} · {ai.provider || "Configured provider"}{ai.model ? ` / ${ai.model}` : ""}{ai.generated_at ? ` · ${new Date(ai.generated_at).toLocaleString()}` : ""}</div>{ai.citations?.length ? <div className="citation-list"><strong>Evidence references</strong>{ai.citations.map((citation) => <span className="badge neutral" key={citation.id}>{pretty(citation.kind)} · {citation.id}</span>)}</div> : null}</> : <div className="secondary">{ai?.message || "No explanation is attached. You can review the source and risk evidence without requesting one."}</div>}
        </div></section>
        <section className="panel"><div className="panel-head"><div><h2>Decision history</h2><div className="secondary">Recorded decisions and workflow events</div></div></div><div className="panel-body">{history.isError && <div className="error" role="alert">History could not be loaded. <button className="button" onClick={() => void history.refetch()}>Retry</button></div>}{timeline.length ? <div className="timeline">{timeline.map((event) => <div className="timeline-item" key={event.event_id}><span className="timeline-dot" aria-hidden="true"/><div><div className="timeline-title">{pretty(event.decision || event.event_type)}{event.decision_origin ? ` · ${pretty(event.decision_origin)}` : ""}</div>{event.comment && <div>{event.comment}</div>}<div className="timeline-meta">{event.actor_sub || "System"} · {new Date(event.created_at).toLocaleString()}</div></div></div>)}</div> : <div className="empty compact-empty">No decision or workflow events are recorded yet.</div>}</div></section>
      </div>
      <aside className="stack decision-panel">
        <section className="panel"><div className="panel-head"><div><h2>Your decision</h2><div className="secondary">{decisionReady ? "Choose the outcome for this observed grant." : "This review is not open for decisions."}</div></div></div><div className="panel-body">
          {item.exception_state === "OPEN" && <div className="notice warning">An open exception is blocking decisions. Ask the campaign administrator to resolve it.</div>}
          {item.campaign_state !== "OPEN" && <div className="notice warning">This campaign is {pretty(item.campaign_state).toLowerCase()}.</div>}
          {item.status !== "PENDING" && <div className="notice">A decision has already been recorded for this review.</div>}
          {decisionReady && canActAsReviewer && <><div className="field"><label htmlFor="comment">Reviewer comment {item.status === "PENDING" ? <span className="optional">(required for revocation)</span> : null}</label><textarea id="comment" className="textarea" maxLength={4000} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Record the reason for your decision. A comment is required to revoke." /></div><div className="decision-actions"><button className="button primary" disabled={decision.isPending || current === false} onClick={() => decide("APPROVED")}>{decision.isPending ? "Saving…" : "Approve grant path"}</button><button className="button danger" disabled={decision.isPending || current === false || !comment.trim()} onClick={() => decide("REVOKED")}>Revoke grant path</button></div>{current === false && <p className="secondary">Decisions are disabled because this snapshot is no longer current.</p>}<p className="decision-disclaimer">Your action is recorded in the certification history. Revoking this path does not prove that all access has been removed.</p></>}
          {decisionReady && !canActAsReviewer && <div className="notice">Read-only evidence view. Only an assigned campaign reviewer can record a decision or request an explanation.</div>}
        </div></section>
        <section className="panel"><div className="panel-head"><h2>Review context</h2></div><div className="panel-body"><dl className="context-list"><EvidenceItem label="Assignment" value={item.assigned_reviewer_sub || "Campaign reviewer"} /><EvidenceItem label="Due date" value={item.due_at ? new Date(item.due_at).toLocaleString() : "No deadline"} /><EvidenceItem label="Evidence state" value={pretty(item.evidence_state)} /><EvidenceItem label="Source coverage" value={item.source_coverage ? "Available" : "Not recorded"} /></dl></div></section>
      </aside>
    </div>
  </>;
}

import { ApiError } from "@/lib/api/client";
