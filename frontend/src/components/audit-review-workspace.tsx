"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api/client";
import { displayDate, pretty, StatusBadge } from "@/components/workspace-ui";

type JsonObject = Record<string, unknown>;
type AuditReview = {
  review_id: string;
  campaign_name: string;
  account_id: string | null;
  source_scope: string | null;
  status: string;
  reviewer_sub: string | null;
  reviewer_comment: string | null;
  review_created_at: string;
  decision_recorded_at: string | null;
  snapshot_id: string | null;
  grant_id: string | null;
  observation_id: string | null;
  risk_assessment_id: string | null;
  principal_name: string;
  policy_name: string;
  policy_document: JsonObject | null;
  observed_at: string | null;
  policy_evidence_status: string;
  missing_policy_reason: string | null;
  policy_version: string | null;
  policy_sha256: string | null;
  snapshot_published_at: string | null;
  risk_level: string;
  risk_rule_version: string | null;
  review_scope: string;
  observed_path: JsonObject | null;
  assessment: JsonObject | null;
  source_manifest: { manifest: JsonObject; sha256: string } | null;
  review_manifest: { manifest: JsonObject; sha256: string } | null;
  evidence_invalidations: Array<{ reason_code: string; detail: string; recorded_at: string }>;
  current_snapshot_eligible: boolean | null;
  decision_history: Array<{ event_id: string; event_type: string; decision?: string; actor_sub?: string; comment?: string; created_at: string }>;
  remediation_history: JsonObject;
};

function Fact({ label, value, mono = false }: { label: string; value: unknown; mono?: boolean }) {
  return <div className="evidence-item"><dt>{label}</dt><dd className={mono ? "mono" : ""}>{value == null || value === "" ? "Not recorded" : String(value)}</dd></div>;
}

export function AuditReviewWorkspace({ reviewId }: { reviewId: string }) {
  const detail = useQuery({
    queryKey: ["audit-review", reviewId],
    queryFn: () => apiFetch<AuditReview>(`audit/reviews/${encodeURIComponent(reviewId)}`),
  });
  if (detail.isLoading) return <div className="loading" role="status">Loading historical review…</div>;
  if (detail.isError || !detail.data) return <div className="error" role="alert"><Link href="/audit" className="row-link">← Back to audit</Link><p>{detail.error instanceof Error ? detail.error.message : "Review evidence could not be loaded."}</p></div>;
  const item = detail.data;
  const assessment = item.assessment;
  const reasons = Array.isArray(assessment?.reason_codes) ? assessment.reason_codes as string[] : [];
  return <>
    <div className="breadcrumb-link"><Link href="/audit" className="row-link">← Audit and exports</Link></div>
    <div className="page-heading"><div><div className="eyebrow">Historical review · {item.review_id}</div><h1>{item.principal_name}</h1><p className="subhead">{item.policy_name} · {item.campaign_name}</p></div><StatusBadge value={item.status}/></div>
    <div className="notice"><strong>Pinned history:</strong> this review and its decision remain tied to the recorded grant path. Current eligibility is a separate check; neither proves effective access.</div>
    {item.review_scope === "LEGACY_UNKNOWN_PATH" && <div className="notice warning" role="status">This legacy review has no verifiable grant-path or manifest binding. Its stored decision remains visible, but missing provenance cannot be reconstructed.</div>}
    {item.current_snapshot_eligible === false && <div className="notice warning" role="status">The bound snapshot is no longer currently eligible. The historical record below is unchanged.</div>}
    {item.evidence_invalidations.map((entry, index) => <div className="notice danger" key={`${entry.reason_code}-${index}`} role="alert"><strong>Evidence invalidated:</strong> {entry.detail} · {pretty(entry.reason_code)} · {displayDate(entry.recorded_at)}</div>)}
    <section className="panel"><div className="panel-head"><div><h2>Frozen review binding</h2><div className="secondary">Identity, attachment, rule, and timestamps captured for this review</div></div></div><div className="panel-body"><dl className="evidence-list">
      <Fact label="AWS account" value={item.account_id}/><Fact label="Source scope" value={item.source_scope}/>
      <Fact label="Principal" value={item.principal_name}/><Fact label="Policy" value={item.policy_name}/>
      <Fact label="Grant type" value={item.observed_path?.grant_type}/><Fact label="Observed source" value={item.observed_path?.source_name}/>
      <Fact label="Source ID" value={item.observed_path?.source_id} mono/><Fact label="Attachment ID" value={item.observed_path?.attachment_id} mono/>
      <Fact label="Grant ID" value={item.grant_id} mono/><Fact label="Observation ID" value={item.observation_id} mono/>
      <Fact label="Policy version" value={item.policy_version}/><Fact label="Policy SHA-256" value={item.policy_sha256} mono/>
      <Fact label="Risk assessment" value={item.risk_assessment_id} mono/><Fact label="Risk rule version" value={item.risk_rule_version}/>
      <Fact label="Observed at" value={item.observed_at ? displayDate(item.observed_at) : null}/><Fact label="Snapshot published" value={item.snapshot_published_at ? displayDate(item.snapshot_published_at) : null}/>
      <Fact label="Review created" value={displayDate(item.review_created_at)}/><Fact label="Decision recorded" value={item.decision_recorded_at ? displayDate(item.decision_recorded_at) : null}/>
      <Fact label="Source manifest SHA-256" value={item.source_manifest?.sha256} mono/><Fact label="Review manifest SHA-256" value={item.review_manifest?.sha256} mono/>
      <Fact label="Current snapshot eligible" value={item.current_snapshot_eligible == null ? "Unknown for legacy review" : item.current_snapshot_eligible ? "Yes" : "No"}/><Fact label="Effective access" value="Not evaluated"/>
    </dl></div></section>
    <section className="panel"><div className="panel-head"><div><h2>Assessment and policy evidence</h2><div className="secondary">The rule conclusion is about this frozen document, not AWS authorization</div></div></div><div className="panel-body"><dl className="evidence-list"><Fact label="Legacy routing" value={item.risk_level}/><Fact label="Pattern severity" value={assessment?.risk_severity ?? "Unknown legacy"}/><Fact label="Assessment status" value={assessment?.assessment_status ?? "Unknown legacy"}/><Fact label="Document confidence" value={assessment?.assessment_confidence ?? "Unknown legacy"}/><Fact label="Policy evidence" value={item.policy_evidence_status}/><Fact label="Missing document reason" value={item.missing_policy_reason}/></dl>{reasons.length > 0 && <p>Rule reasons: {reasons.map(pretty).join("; ")}</p>}{item.policy_document && <details className="policy-details"><summary>Exact frozen policy document</summary><pre className="policy">{JSON.stringify(item.policy_document, null, 2)}</pre></details>}{assessment && <details className="policy-details"><summary>Exact grant assessment</summary><pre className="policy">{JSON.stringify(assessment, null, 2)}</pre></details>}</div></section>
    <section className="panel"><div className="panel-head"><div><h2>Decision and workflow history</h2><div className="secondary">Actor, rationale, and event time</div></div></div><div className="panel-body"><dl className="evidence-list"><Fact label="Decision" value={item.status}/><Fact label="Reviewer" value={item.reviewer_sub}/><Fact label="Recorded comment" value={item.reviewer_comment}/></dl>{item.decision_history.length ? <ol className="timeline">{item.decision_history.map((event) => <li className="timeline-item" key={event.event_id}><span className="timeline-dot" aria-hidden="true"/><div><strong>{pretty(event.decision ?? event.event_type)}</strong><div>{event.comment}</div><div className="timeline-meta">{event.actor_sub || "System"} · {displayDate(event.created_at)}</div></div></li>)}</ol> : <p className="secondary">No immutable decision event is available for this historical row.</p>}<details className="event-details"><summary>Remediation event history</summary><pre className="policy">{JSON.stringify(item.remediation_history, null, 2)}</pre></details></div></section>
    <section className="panel"><div className="panel-head"><div><h2>Manifest reconstruction</h2><div className="secondary">Canonical source and review manifest bodies corresponding to the hashes above</div></div></div><div className="panel-body">{item.source_manifest && <details className="event-details"><summary>Source evidence manifest</summary><pre className="policy">{JSON.stringify(item.source_manifest.manifest, null, 2)}</pre></details>}{item.review_manifest && <details className="event-details"><summary>Review evidence manifest</summary><pre className="policy">{JSON.stringify(item.review_manifest.manifest, null, 2)}</pre></details>}{!item.source_manifest && <p className="secondary">No source manifest can be reconstructed for this legacy review.</p>}</div></section>
  </>;
}
