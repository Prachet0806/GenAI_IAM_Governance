"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, apiFetch } from "@/lib/api/client";
import { ConfirmDialog, displayDate, EmptyState, MetricCard, Pagination, pretty, StatusBadge } from "./workspace-ui";

type Row = Record<string, unknown>;
type List = { [key: string]: unknown; total?: number; limit?: number; offset?: number; has_more?: boolean; next_offset?: number | null };
const PAGE_SIZE = 25;
const text = (value: unknown) => value == null || value === "" ? "Not recorded" : String(value);
const field = (label: string, value: unknown, mono = false) => <div className="evidence-item" key={label}><dt>{label}</dt><dd className={mono ? "mono" : ""}>{text(value)}</dd></div>;

function useData<T>(key: string, path: string, enabled = true) {
  return useQuery({ queryKey: [key, path], queryFn: () => apiFetch<T>(path), enabled });
}

function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof ApiError && error.status === 403
    ? "Your account does not have access to this workspace or data."
    : error instanceof Error ? error.message : "The request could not be completed.";
  return <div className="error" role="alert">{message}{error instanceof ApiError && error.status === 401 && <> <Link className="row-link" href="/login">Sign in again</Link></>}</div>;
}

function Heading({ eyebrow, heading, subtitle, action }: { eyebrow: string; heading: string; subtitle: string; action?: React.ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{heading}</h1><p className="subhead">{subtitle}</p></div>{action}</div>;
}

function SectionTitle({ title, detail, count }: { title: string; detail?: string; count?: unknown }) {
  return <div className="panel-head"><div><h2>{title}</h2>{detail && <div className="secondary">{detail}</div>}</div>{count !== undefined && <span className="secondary">{text(count)} in scope</span>}</div>;
}

function ProgressBar({ value }: { value: unknown }) {
  const amount = Math.min(100, Math.max(0, Number(value) || 0));
  return <div className="progress-track" role="progressbar" aria-label="Campaign completion" aria-valuemin={0} aria-valuemax={100} aria-valuenow={amount}><span style={{ width: `${amount}%` }} /></div>;
}

function Timeline({ rows, empty, linkReviews = false }: { rows: Row[]; empty: string; linkReviews?: boolean }) {
  if (!rows.length) return <EmptyState title={empty} />;
  return <ol className="timeline">{rows.map((row, index) => <li className="timeline-item" key={text(row.event_id ?? row.id ?? index)}><span className="timeline-dot" aria-hidden="true" /><div><div className="timeline-title">{pretty(row.summary ?? row.event_type ?? row.action ?? row.event_type)}</div><div className="timeline-meta">{displayDate(row.created_at ?? row.approved_at ?? row.timestamp)} · {text(row.actor_sub ?? row.actor_id ?? row.approver_sub ?? "System")}</div>{Boolean(row.comment) && <p>{text(row.comment)}</p>}{Boolean(row.review_id) && linkReviews && <Link className="row-link" href={`/reviews/${encodeURIComponent(String(row.review_id))}`}>Open originating review</Link>}{Boolean(row.review_id) && !linkReviews && <div className="timeline-meta">Review reference: {text(row.review_id)}</div>}{Boolean(row.details) && <details className="event-details"><summary>View recorded details</summary><pre className="policy">{JSON.stringify(row.details, null, 2)}</pre></details>}</div></li>)}</ol>;
}

export function CampaignWorkspace({ campaignId }: { campaignId?: string }) {
  const router = useRouter();
  const qc = useQueryClient();
  const [message, setMessage] = useState("");
  const [snapshot, setSnapshot] = useState("");
  const [readiness, setReadiness] = useState<Row | null>(null);
  const [name, setName] = useState("");
  const [due, setDue] = useState("");
  const [reviewer, setReviewer] = useState("");
  const [reviewerSub, setReviewerSub] = useState("");
  const [bulkReviewer, setBulkReviewer] = useState("");
  const [removeReviewer, setRemoveReviewer] = useState("");
  const [reviewAssign, setReviewAssign] = useState("");
  const [selectedReviews, setSelectedReviews] = useState<string[]>([]);
  const [exceptionReason, setExceptionReason] = useState("");
  const [campaignState, setCampaignState] = useState("");
  const [listOffset, setListOffset] = useState(0);
  const [snapshotOffset, setSnapshotOffset] = useState(0);
  const [reviewOffset, setReviewOffset] = useState(0);
  const [eventOffset, setEventOffset] = useState(0);
  const [reviewStatus, setReviewStatus] = useState("");
  const [confirm, setConfirm] = useState<{ title: string; summary: string; action: () => Promise<void> } | null>(null);
  const list = useData<List>("campaigns", `campaigns?limit=${PAGE_SIZE}&offset=${listOffset}${campaignState ? `&state=${campaignState}` : ""}`, !campaignId);
  const snapshots = useData<List>("snapshots", `snapshots?limit=${PAGE_SIZE}&offset=${snapshotOffset}`, !campaignId);
  const campaign = useData<Row>("campaign", `campaigns/${campaignId ?? ""}`, Boolean(campaignId));
  const progress = useData<Row>("progress", `campaigns/${campaignId}/progress`, Boolean(campaignId));
  const assignments = useData<List>("campaign-reviewers", `campaigns/${campaignId}/reviewers`, Boolean(campaignId));
  const reviews = useData<List>("campaign-reviews", `campaigns/${campaignId}/reviews?limit=${PAGE_SIZE}&offset=${reviewOffset}${reviewStatus ? `&status=${reviewStatus}` : ""}`, Boolean(campaignId));
  const events = useData<List>("campaign-events", `campaigns/${campaignId}/events?limit=${PAGE_SIZE}&offset=${eventOffset}`, Boolean(campaignId));
  const campaignRows = (list.data?.campaigns as Row[] | undefined) ?? [];
  const snapshotRows = (snapshots.data?.snapshots as Row[] | undefined) ?? [];
  const run = async (path: string, method: string, body?: Row) => {
    setMessage("");
    try {
      const result = await apiFetch<Row>(path, { method, ...(body ? { body: JSON.stringify(body) } : {}) });
      setMessage("The change was recorded.");
      await qc.invalidateQueries();
      return result;
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The request failed. Please try again.");
      return {};
    }
  };
  const checkSnapshot = async (id: string) => {
    setSnapshot(id); setReadiness(null); setMessage("");
    if (!id) return;
    try { setReadiness(await apiFetch<Row>(`snapshots/${encodeURIComponent(id)}/readiness`)); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Readiness could not be checked."); }
  };

  if (!campaignId) return <>
    <Heading eyebrow="Campaign administration" heading="Certification campaigns" subtitle="Create campaigns from eligible published evidence, allocate reviewers and follow completion." action={<a className="button primary" href="#create-campaign">Create campaign</a>} />
    <ErrorBox error={list.error} />
    <section className="panel"><div className="panel-head"><div><h2>Campaign portfolio</h2><div className="secondary">Status and reviewer progress for the selected account scope</div></div><span className="secondary">{list.data?.total ?? 0} campaigns</span></div>
      <div className="filters"><div className="field"><label htmlFor="campaign-state-filter">Lifecycle</label><select id="campaign-state-filter" className="select" value={campaignState} onChange={(e) => { setCampaignState(e.target.value); setListOffset(0); }}><option value="">All states</option><option value="OPEN">Open</option><option value="PAUSED">Paused</option><option value="CLOSED">Closed</option></select></div></div>
      {list.isLoading ? <div className="loading" role="status">Loading campaigns…</div> : campaignRows.length === 0 ? <EmptyState title="No campaigns in this view" detail="Create a campaign from a ready snapshot to start a certification cycle." /> : <div className="table-wrap"><table><thead><tr><th>Campaign</th><th>Account and evidence</th><th>Lifecycle</th><th>Reviews</th><th>Progress</th><th>Needs attention</th></tr></thead><tbody>{campaignRows.map((row) => {
        const complete = Number(row.approved ?? 0) + Number(row.revoked ?? 0);
        const total = Number(row.total_reviews ?? 0);
        const percent = total ? complete / total * 100 : 0;
        return <tr key={text(row.campaign_id)}><td><Link className="row-link" href={`/campaigns/${encodeURIComponent(String(row.campaign_id))}`}>{text(row.name)}</Link><div className="secondary">Created {displayDate(row.created_at, false)}</div></td><td>{text(row.account_id)}<div className="secondary mono">Snapshot {text(row.snapshot_id).slice(0, 14)}</div></td><td><StatusBadge value={row.state} /></td><td>{complete} / {total}<div className="secondary">{text(row.pending ?? 0)} awaiting review</div></td><td><div className="progress-cell"><ProgressBar value={percent} /><span>{percent.toFixed(0)}%</span></div></td><td>{text(row.overdue ?? 0)} overdue<div className="secondary">{text(row.open_exceptions ?? 0)} open exceptions</div></td></tr>;
      })}</tbody></table></div>}
      {list.data && <Pagination offset={listOffset} limit={Number(list.data.limit ?? PAGE_SIZE)} total={Number(list.data.total ?? 0)} hasMore={Boolean(list.data.has_more)} busy={list.isFetching} onPage={setListOffset} />}
    </section>
    <section className="panel create-panel" id="create-campaign"><SectionTitle title="Create a campaign" detail="Every review is pinned to one published snapshot." />
      <div className="panel-body stack"><ErrorBox error={snapshots.error} />
        <div className="field"><label htmlFor="snapshot-select">Published snapshot</label><select id="snapshot-select" className="select" value={snapshot} onChange={(e) => void checkSnapshot(e.target.value)}><option value="">Select snapshot evidence</option>{snapshotRows.map((item) => <option key={text(item.snapshot_id)} value={text(item.snapshot_id)}>{text(item.account_id)} · {pretty(item.source_scope)} · {text(item.snapshot_id).slice(0, 12)} · {item.eligible_for_campaign ? "Ready" : "Blocked"}</option>)}</select>
          {snapshots.data && <Pagination offset={snapshotOffset} limit={Number(snapshots.data.limit ?? PAGE_SIZE)} total={Number(snapshots.data.total ?? 0)} hasMore={Boolean(snapshots.data.has_more)} busy={snapshots.isFetching} onPage={setSnapshotOffset} />}</div>
        {readiness && <div className={`notice ${readiness.eligible_for_campaign ? "" : "warning"}`}><strong>{readiness.eligible_for_campaign ? "Evidence is ready" : "Campaign creation is blocked"}</strong><dl className="evidence-list compact-evidence">{field("AWS account", readiness.account_id)}{field("Source scope", pretty(readiness.source_scope))}{field("Reviewable grant paths", readiness.reviewable_grants)}{field("Published snapshot", readiness.published_snapshot_id, true)}{field("Latest discovery", pretty(readiness.latest_attempt_status))}</dl>{Array.isArray(readiness.blockers) && <ul>{(readiness.blockers as Row[]).map((blocker, index) => <li key={`${text(blocker.code)}-${index}`}>{text(blocker.message)}</li>)}</ul>}</div>}
        <div className="form-grid"><div className="field"><label htmlFor="campaign-name">Campaign name</label><input id="campaign-name" className="input" minLength={3} maxLength={120} value={name} onChange={(e) => setName(e.target.value)} placeholder="Quarterly access certification" /></div><div className="field"><label htmlFor="campaign-due">Deadline <span className="optional">Optional</span></label><input id="campaign-due" type="datetime-local" className="input" value={due} onChange={(e) => setDue(e.target.value)} /></div></div>
        {Boolean(readiness?.eligible_for_campaign) && <div className="campaign-preview"><span>Campaign preview</span><strong>{text(readiness?.reviewable_grants)} reviews</strong><span>{text(readiness?.account_id)} · {pretty(readiness?.source_scope)}</span></div>}
        <button className="button primary align-start" disabled={!readiness?.eligible_for_campaign || name.trim().length < 3} onClick={async () => { try { const result = await run("campaigns", "POST", { name: name.trim(), snapshot_id: snapshot, ...(due ? { due_at: new Date(due).toISOString() } : {}) }); if (result.campaign_id) router.push(`/campaigns/${encodeURIComponent(String(result.campaign_id))}`); } catch { /* message is rendered below */ } }}>Create campaign</button>
        {message && <div className="notice" role="status">{message}</div>}
      </div>
    </section>
  </>;

  const reviewRows = (reviews.data?.reviews as Row[] | undefined) ?? [];
  const reviewerRows = (assignments.data?.reviewers as Row[] | undefined) ?? [];
  const eventRows = (events.data?.events as Row[] | undefined) ?? [];
  const completed = Number(progress.data?.completed ?? 0);
  const total = Number(progress.data?.total ?? 0);
  return <>
    <div className="breadcrumb-link"><Link className="row-link" href="/campaigns">← Campaigns</Link></div>
    <Heading eyebrow="Campaign administration" heading={text(campaign.data?.name ?? "Campaign detail")} subtitle={`${text(campaign.data?.account_id)} · ${pretty(campaign.data?.source_scope)} · Snapshot ${text(campaign.data?.snapshot_id)}`} />
    <ErrorBox error={campaign.error ?? progress.error ?? reviews.error} />
    <section className="campaign-progress panel"><div className="campaign-progress-top"><div><span>Campaign completion</span><strong>{text(progress.data?.completion_percent ?? 0)}%</strong></div><StatusBadge value={campaign.data?.state} /></div><ProgressBar value={progress.data?.completion_percent} /><div className="campaign-progress-meta"><span>{completed} of {total} decisions recorded</span><span>{text(progress.data?.pending ?? 0)} awaiting · {text(progress.data?.overdue ?? 0)} overdue</span></div></section>
    <section className="cards" aria-label="Campaign status"><MetricCard label="Pending" value={text(progress.data?.pending ?? "—")} note="Awaiting a reviewer decision"/><MetricCard label="Overdue" value={text(progress.data?.overdue ?? "—")} note="Pending past the deadline"/><MetricCard label="High risk" value={text(progress.data?.high_risk ?? "—")} note="Prioritize careful evidence review"/><MetricCard label="Open exceptions" value={text(progress.data?.open_exceptions ?? "—")} note="Block review decisions"/></section>
    {message && <div className="notice" role="status">{message}</div>}
    <section className="panel"><SectionTitle title="Campaign controls" detail="Changes are recorded in campaign history."/><div className="panel-body"><div className="form-grid"><div className="field"><label htmlFor="lifecycle-state">Lifecycle state</label><select id="lifecycle-state" className="select" value={text(campaign.data?.state)} onChange={(e) => setConfirm({ title: `${pretty(e.target.value)} this campaign?`, summary: e.target.value === "CLOSED" ? "Closing stops further review decisions for this campaign." : `The campaign will move to ${pretty(e.target.value)}.`, action: async () => { await run(`campaigns/${campaignId}/state`, "POST", { state: e.target.value }); setConfirm(null); } })}><option>OPEN</option><option>PAUSED</option><option>CLOSED</option></select></div><div className="field"><label htmlFor="campaign-owner">Campaign owner subject</label><input id="campaign-owner" className="input" defaultValue={text(campaign.data?.owner_sub)} placeholder="OIDC subject" /></div><div className="field"><label htmlFor="campaign-deadline">Campaign deadline</label><input id="campaign-deadline" className="input" type="datetime-local" defaultValue={typeof campaign.data?.due_at === "string" ? new Date(String(campaign.data.due_at)).toISOString().slice(0, 16) : ""}/></div></div><div className="decision-actions"><button className="button" onClick={() => { const input = document.getElementById("campaign-owner") as HTMLInputElement; if (input.value.trim()) void run(`campaigns/${campaignId}/owner`, "POST", { owner_sub: input.value.trim() }); }}>Save owner</button><button className="button" onClick={() => { const input = document.getElementById("campaign-deadline") as HTMLInputElement; if (input.value) void run(`campaigns/${campaignId}/deadline`, "POST", { due_at: new Date(input.value).toISOString() }); }}>Save deadline</button></div></div></section>
    <div className="detail-grid campaign-detail-grid"><section className="panel"><SectionTitle title="Review coverage" detail="Assignments and decisions by reviewer"/>
      <div className="table-wrap"><table><thead><tr><th>Reviewer identity</th><th>Assigned</th><th>Pending</th><th>Completed</th><th>Coverage</th></tr></thead><tbody>{reviewerRows.map((row) => { const count = Number(row.assigned ?? 0); const done = Number(row.completed ?? 0); return <tr key={text(row.reviewer_sub)}><td><span className="mono">{text(row.reviewer_sub)}</span><div className="secondary">Assigned {displayDate(row.assigned_at, false)}</div></td><td>{count}</td><td>{text(row.pending ?? 0)}</td><td>{done}</td><td><div className="progress-cell"><ProgressBar value={count ? done / count * 100 : 0}/><span>{count ? Math.round(done / count * 100) : 0}%</span></div></td></tr>; })}</tbody></table>{reviewerRows.length === 0 && <EmptyState title="No reviewers allocated" detail="Assign a reviewer to distribute campaign review work."/>}</div>
      <div className="panel-body stack"><div className="notice warning">Reviewer subjects are entered manually and are not checked against an identity-provider directory. Verify the OIDC subject and reviewer-group membership before assigning.</div><div className="form-grid"><div className="field"><label htmlFor="reviewer-subject">Reviewer OIDC subject</label><input id="reviewer-subject" className="input" value={reviewer} onChange={(e) => setReviewer(e.target.value)} /></div><button className="button" disabled={!reviewer.trim()} onClick={() => setConfirm({ title: "Assign this reviewer?", summary: `The OIDC subject ${reviewer.trim()} will be eligible for campaign review work.`, action: async () => { await run(`campaigns/${campaignId}/reviewers`, "POST", { reviewer_sub: reviewer.trim() }); setReviewer(""); setConfirm(null); } })}>Assign reviewer</button></div><div className="form-grid"><div className="field"><label htmlFor="review-to-reassign">Review ID</label><input id="review-to-reassign" className="input" value={reviewAssign} onChange={(e) => setReviewAssign(e.target.value)} /></div><div className="field"><label htmlFor="new-reviewer-subject">New reviewer OIDC subject</label><input id="new-reviewer-subject" className="input" value={reviewerSub} onChange={(e) => setReviewerSub(e.target.value)} /></div><button className="button" disabled={!reviewAssign.trim() || !reviewerSub.trim()} onClick={() => setConfirm({ title: "Reassign this review?", summary: `Review ${reviewAssign.trim()} will be assigned to ${reviewerSub.trim()}.`, action: async () => { await run(`reviews/${encodeURIComponent(reviewAssign.trim())}/assignment`, "POST", { reviewer_sub: reviewerSub.trim() }); setReviewAssign(""); setReviewerSub(""); setConfirm(null); } })}>Reassign review</button></div><div className="form-grid"><div className="field"><label htmlFor="remove-reviewer">Remove reviewer from campaign</label><select id="remove-reviewer" className="select" value={removeReviewer} onChange={(e) => setRemoveReviewer(e.target.value)}><option value="">Select reviewer</option>{reviewerRows.map((row) => <option key={text(row.reviewer_sub)} value={text(row.reviewer_sub)}>{text(row.reviewer_sub)}</option>)}</select></div><button className="button danger" disabled={!removeReviewer} onClick={() => setConfirm({ title: "Remove this reviewer?", summary: `The reviewer ${removeReviewer} will be removed from campaign eligibility. Existing review history is retained.`, action: async () => { await run(`campaigns/${campaignId}/reviewers?reviewer_sub=${encodeURIComponent(removeReviewer)}`, "DELETE"); setRemoveReviewer(""); setConfirm(null); } })}>Remove reviewer</button></div></div>
      <div className="panel-divider"><SectionTitle title="Review records" detail="Filter by decision state, resolve exceptions, or reassign selected pending reviews."/></div><div className="filters"><div className="field"><label htmlFor="review-status">Decision state</label><select id="review-status" className="select" value={reviewStatus} onChange={(e) => { setReviewStatus(e.target.value); setReviewOffset(0); setSelectedReviews([]); }}><option value="">All reviews</option><option value="PENDING">Pending</option><option value="APPROVED">Approved</option><option value="REVOKED">Revoked</option></select></div></div>
      <div className="filters bulk-assignment"><div className="field grow"><label htmlFor="bulk-reviewer">Assign selected pending reviews to</label><input id="bulk-reviewer" className="input" value={bulkReviewer} onChange={(e) => setBulkReviewer(e.target.value)} placeholder="Reviewer OIDC subject"/></div><button className="button" disabled={!selectedReviews.length || !bulkReviewer.trim()} onClick={() => setConfirm({ title: `Assign ${selectedReviews.length} selected reviews?`, summary: `Selected pending reviews will be assigned to ${bulkReviewer.trim()}. Each review is updated separately, so some assignments may succeed if another request fails.`, action: async () => { const outcomes = await Promise.allSettled(selectedReviews.map((id) => apiFetch(`reviews/${encodeURIComponent(id)}/assignment`, { method: "POST", body: JSON.stringify({ reviewer_sub: bulkReviewer.trim() }) }))); const succeeded = outcomes.filter((outcome) => outcome.status === "fulfilled").length; const failed = outcomes.length - succeeded; setMessage(`${succeeded} review${succeeded === 1 ? "" : "s"} assigned${failed ? `; ${failed} failed and need review` : ""}.`); if (!failed) { setSelectedReviews([]); setBulkReviewer(""); } await qc.invalidateQueries(); setConfirm(null); } })}>Assign selected ({selectedReviews.length})</button></div>
      <div className="table-wrap"><table><thead><tr><th><label className="selection-label"><input type="checkbox" aria-label="Select all pending reviews on this page" checked={reviewRows.filter((row) => row.status === "PENDING").length > 0 && reviewRows.filter((row) => row.status === "PENDING").every((row) => selectedReviews.includes(String(row.review_id)))} onChange={(event) => setSelectedReviews(event.target.checked ? reviewRows.filter((row) => row.status === "PENDING").map((row) => String(row.review_id)) : [])}/><span>Assign</span></label></th><th>Principal and grant</th><th>Risk</th><th>Decision</th><th>Reviewer</th><th>Deadline</th><th>Exception</th><th>Review</th></tr></thead><tbody>{reviewRows.map((row) => <tr key={text(row.review_id)}><td><input type="checkbox" aria-label={`Select review ${text(row.review_id)}`} disabled={row.status !== "PENDING"} checked={selectedReviews.includes(String(row.review_id))} onChange={(event) => setSelectedReviews((current) => event.target.checked ? [...new Set([...current, String(row.review_id)])] : current.filter((id) => id !== String(row.review_id)))}/></td><td><div className="principal">{text(row.principal)}</div><div className="secondary">{text(row.grant_name)} · {text(row.account_id)}</div></td><td><StatusBadge value={row.risk_level}/></td><td><StatusBadge value={row.status}/></td><td className="mono">{text(row.assigned_reviewer_sub)}</td><td>{displayDate(row.due_at, false)}</td><td><StatusBadge value={row.exception_state}/>{row.exception_state === "OPEN" && <div className="exception-action"><input aria-label={`Exception reason for ${text(row.review_id)}`} className="input" value={exceptionReason} onChange={(e) => setExceptionReason(e.target.value)} placeholder="Resolution reason"/><button className="button" disabled={!exceptionReason.trim()} onClick={() => setConfirm({ title: "Resolve this exception?", summary: `The reason will be attached to review ${text(row.review_id)} and retained in its history.`, action: async () => { await run(`reviews/${encodeURIComponent(String(row.review_id))}/exception/resolve`, "POST", { reason: exceptionReason.trim() }); setExceptionReason(""); setConfirm(null); } })}>Resolve</button></div>}</td><td><Link className="row-link" href={`/reviews/${encodeURIComponent(String(row.review_id))}`}>Open review</Link></td></tr>)}</tbody></table>{reviewRows.length === 0 && <EmptyState title="No reviews match this state"/>}</div>
      {reviews.data && <Pagination offset={Number(reviews.data.offset ?? reviewOffset)} limit={Number(reviews.data.limit ?? PAGE_SIZE)} total={Number(reviews.data.total ?? 0)} hasMore={Boolean(reviews.data.has_more)} busy={reviews.isFetching} onPage={(nextOffset) => { setReviewOffset(nextOffset); setSelectedReviews([]); }}/>}</section>
      <div className="stack"><section className="panel"><SectionTitle title="Campaign activity" detail="Lifecycle and assignment history"/><div className="panel-body"><Timeline rows={eventRows} empty="No campaign events recorded yet." linkReviews/></div>{events.data && <Pagination offset={eventOffset} limit={Number(events.data.limit ?? PAGE_SIZE)} total={Number(events.data.total ?? 0)} hasMore={Boolean(events.data.has_more)} busy={events.isFetching} onPage={setEventOffset}/>}</section>
        <section className="panel"><SectionTitle title="Risk distribution" detail="Risk levels across the frozen review set"/><div className="panel-body risk-distribution">{[["High", progress.data?.high_risk, "high"], ["Medium", progress.data?.medium_risk, "medium"], ["Low", progress.data?.low_risk, "low"], ["Unknown", progress.data?.unknown_risk, "unknown"]].map(([label, value, tone]) => <div className="risk-row" key={String(label)}><span className={`risk-swatch ${String(tone)}`}/><span>{text(label)}</span><strong>{text(value ?? "—")}</strong></div>)}</div></section></div></div>
    {confirm && <ConfirmDialog title={confirm.title} summary={<p>{confirm.summary}</p>} confirmLabel="Confirm change" onCancel={() => setConfirm(null)} onConfirm={() => void confirm.action()}/>}
  </>;
}

export function RemediationWorkspace({ reviewId }: { reviewId?: string }) {
  const qc = useQueryClient();
  const [offset, setOffset] = useState(0);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  const [decision, setDecision] = useState<"APPROVED" | "DECLINED">("APPROVED");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const queue = useData<List>("approvals", `approvals?limit=${PAGE_SIZE}&offset=${offset}`, !reviewId);
  const detail = useData<Row>("approval-detail", `approvals/${reviewId ?? ""}`, Boolean(reviewId));
  const items = (queue.data?.items as Row[] | undefined) ?? [];
  const submit = async () => {
    try {
      await apiFetch(`approvals/${encodeURIComponent(reviewId!)}/decision`, { method: "POST", body: JSON.stringify({ decision, reason: reason.trim() }) });
      setConfirmOpen(false); setMessage(`Independent ${decision.toLowerCase()} decision recorded. This is not proof of AWS execution.`);
      await qc.invalidateQueries();
    } catch (error) { setConfirmOpen(false); setMessage(error instanceof Error ? error.message : "Decision failed. Please retry."); }
  };
  if (!reviewId) return <>
    <Heading eyebrow="Independent control" heading="Remediation approvals" subtitle="Check exact grant evidence and eligibility blockers before recording an independent approval."/>
    <ErrorBox error={queue.error}/><section className="panel"><SectionTitle title="Approval inbox" detail="Each request follows an authenticated reviewer revoke decision." count={queue.data?.total ?? 0}/>
      {queue.isLoading ? <div className="loading" role="status">Loading approval requests…</div> : items.length === 0 ? <EmptyState title="No requests in this view" detail="Eligible and blocked requests from revoked review decisions appear here."/> : <div className="table-wrap"><table><thead><tr><th>Principal and grant</th><th>Account</th><th>Original decision</th><th>Eligibility</th><th>Workflow</th><th></th></tr></thead><tbody>{items.map((item) => <tr key={text(item.review_id)}><td><div className="principal">{text(item.principal)}</div><div className="secondary">{text(item.grant_name)} · {pretty(item.action_type)}</div></td><td>{text(item.account_id)}</td><td><StatusBadge value={item.status}/><div className="secondary">Risk {pretty(item.risk_level)}</div></td><td><StatusBadge value={item.eligible ? "ELIGIBLE" : "BLOCKED"}/><div className="secondary">{Array.isArray(item.blockers) ? item.blockers.length : 0} blockers</div></td><td><StatusBadge value={item.workflow_state}/></td><td><Link className="row-link" href={`/remediation/${encodeURIComponent(String(item.review_id))}`}>Inspect request</Link></td></tr>)}</tbody></table></div>}
      {queue.data && <Pagination offset={offset} limit={Number(queue.data.limit ?? PAGE_SIZE)} total={Number(queue.data.total ?? 0)} hasMore={Boolean(queue.data.has_more)} busy={queue.isFetching} onPage={setOffset}/>}</section>
  </>;
  const rem = detail.data?.remediation as Row | undefined;
  const review = detail.data?.review as Row | undefined;
  const blockers = (rem?.blockers as Row[] | undefined) ?? [];
  const history = rem?.history as Row | undefined;
  const historyRows = [...((history?.approval_events as Row[] | undefined) ?? []), ...((history?.action_events as Row[] | undefined) ?? []), ...((history?.reconciliation_events as Row[] | undefined) ?? [])].sort((a, b) => String(a.created_at ?? a.approved_at ?? "").localeCompare(String(b.created_at ?? b.approved_at ?? "")));
  const declineHardStops = new Set(["REVIEW_NOT_REVOKED", "SELF_APPROVAL", "REVIEWER_IDENTITY_MISSING", "AUTHENTICATED_REVOCATION_REQUIRED", "EVIDENCE_NOT_PINNED", "ALREADY_APPROVED", "ALREADY_DECLINED"]);
  const declineBlocked = blockers.some((blocker) => declineHardStops.has(String(blocker.code)));
  return <>
    <div className="breadcrumb-link"><Link className="row-link" href="/remediation">← Approval inbox</Link></div>
    <Heading eyebrow="Independent remediation approval" heading={text(rem?.grant_name ?? reviewId)} subtitle={`${text(rem?.principal)} · ${text(rem?.account_id)} · ${pretty(rem?.source_scope)}`}/>
    <ErrorBox error={detail.error}/>
    {message && <div className="notice" role="status">{message}</div>}
    <div className="notice warning"><strong>Approval is authorization, not execution evidence.</strong> A revoke applies to this observed grant path. It does not prove the principal has lost all effective access.</div>
    <section className="cards"><MetricCard label="Workflow" value={<StatusBadge value={rem?.execution_state ?? "AWAITING_APPROVAL"}/>} note="Current recorded remediation state"/><MetricCard label="Eligibility" value={<StatusBadge value={rem?.eligible ? "ELIGIBLE" : "BLOCKED"}/>} note={`${blockers.length} current blockers`}/><MetricCard label="Requested AWS action" value={pretty(rem?.action_type)} note={pretty(rem?.grant_type)}/><MetricCard label="Risk" value={<StatusBadge value={rem?.risk_level}/>} note="From pinned review evidence"/></section>
    <div className="detail-grid"><div className="stack">
      <section className="panel"><SectionTitle title="Exact grant evidence" detail="Identity and policy values from the review's bound snapshot"/><div className="panel-body"><dl className="evidence-list">{field("Principal", rem?.principal)}{field("Principal ARN", rem?.principal_arn, true)}{field("AWS account", rem?.account_id)}{field("Grant or policy", rem?.grant_name)}{field("Policy version", review?.policy_version)}{field("Policy SHA-256", review?.policy_sha256, true)}{field("Grant type", pretty(rem?.grant_type))}{field("Requested action", pretty(rem?.action_type))}{field("Source scope", pretty(rem?.source_scope))}{field("Snapshot ID", rem?.snapshot_id, true)}{field("Grant ID", rem?.grant_id, true)}{field("Observation ID", rem?.observation_id, true)}{field("Risk assessment", rem?.risk_assessment_id, true)}</dl></div></section>
      <section className="panel"><SectionTitle title="Eligibility checks" detail="The action remains blocked while any required preflight check fails"/><div className="panel-body">{blockers.length ? <ul className="blocker-list">{blockers.map((blocker, index) => <li key={`${text(blocker.code)}-${index}`}><StatusBadge value="BLOCKED"/><div><strong>{pretty(blocker.code)}</strong><p>{text(blocker.message)}</p></div></li>)}</ul> : <div className="notice">All current preflight checks passed. Execution remains a separate workflow outcome.</div>}</div></section>
      <section className="panel"><SectionTitle title="Approval and execution history" detail="An approval event never implies an AWS action succeeded"/><div className="panel-body"><Timeline rows={historyRows} empty="No approval, action, or reconciliation events recorded."/></div></section>
    </div><section className="panel"><SectionTitle title="Original reviewer decision" detail="Independent approvers cannot approve their own revoke decision"/><div className="panel-body"><dl className="evidence-list single-evidence">{field("Decision", review?.status)}{field("Reviewer", rem?.reviewer_sub, true)}{field("Reviewer comment", rem?.reviewer_comment)}{field("Campaign", rem?.campaign_name)}</dl>
      <div className="notice warning">This decision authorizes only the requested controlled workflow and exact target. Review other observed grant paths before drawing conclusions about effective access.</div>
      <div className="field"><label htmlFor="approval-decision">Your independent decision</label><select className="select" id="approval-decision" value={decision} onChange={(e) => setDecision(e.target.value as "APPROVED" | "DECLINED")}><option value="APPROVED">Approve remediation</option><option value="DECLINED">Decline remediation</option></select></div>
      <div className="field form-space"><label htmlFor="approval-reason">Reason <span className="optional">Required and audited</span></label><textarea id="approval-reason" className="textarea" maxLength={4000} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Explain the independent approval or decline decision"/></div>
      <button className="button primary full-width form-space" disabled={!reason.trim() || (decision === "APPROVED" ? blockers.length > 0 : declineBlocked)} onClick={() => setConfirmOpen(true)}>Review {decision.toLowerCase()} decision</button>
      {decision === "APPROVED" && blockers.length > 0 && <p className="secondary">Approval is disabled while preflight blockers remain.</p>}{decision === "DECLINED" && declineBlocked && <p className="secondary">Decline is unavailable because a required identity or evidence condition is not met.</p>}
    </div></section></div>
    {confirmOpen && <ConfirmDialog title={`Record ${decision.toLowerCase()}?`} summary={<><p>{decision === "APPROVED" ? "This records independent authorization for the controlled remediation workflow." : "This records an independent decline and its audited reason."}</p><dl className="evidence-list compact-evidence">{field("Principal", rem?.principal)}{field("AWS account", rem?.account_id)}{field("Exact grant", rem?.grant_name)}{field("Requested action", pretty(rem?.action_type))}</dl><p className="decision-disclaimer">Recording approval does not confirm that remediation ran or succeeded.</p></>} confirmLabel="Record decision" busy={false} onCancel={() => setConfirmOpen(false)} onConfirm={() => void submit()}/>}
  </>;
}

export function AuditWorkspace() {
  const qc = useQueryClient();
  const [campaignId, setCampaignId] = useState("");
  const [accountId, setAccountId] = useState("");
  const [principal, setPrincipal] = useState("");
  const [actorSub, setActorSub] = useState("");
  const [decision, setDecision] = useState("");
  const [eventType, setEventType] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [offset, setOffset] = useState(0);
  const [exportOffset, setExportOffset] = useState(0);
  const [message, setMessage] = useState("");
  const query = useMemo(() => new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset), ...(campaignId ? { campaign_id: campaignId } : {}), ...(accountId ? { account_id: accountId } : {}), ...(principal ? { principal } : {}), ...(actorSub ? { actor_sub: actorSub } : {}), ...(decision ? { decision } : {}), ...(eventType ? { event_type: eventType } : {}), ...(since ? { since: new Date(since).toISOString() } : {}), ...(until ? { until: new Date(until).toISOString() } : {}) }).toString(), [campaignId, accountId, principal, actorSub, decision, eventType, since, until, offset]);
  const events = useData<List>("audit-events", `audit/events?${query}`);
  const exports = useData<List>("exports", `exports?limit=${PAGE_SIZE}&offset=${exportOffset}`);
  const campaigns = useData<List>("audit-campaigns", `campaigns?limit=100&offset=0`);
  const rows = (events.data?.events as Row[] | undefined) ?? [];
  const exportRows = (exports.data?.exports as Row[] | undefined) ?? [];
  const createExport = async () => {
    try {
      const result = await apiFetch<Row>("exports", { method: "POST", body: JSON.stringify({ ...(campaignId ? { campaign_id: campaignId } : {}), ...(accountId ? { account_id: accountId } : {}) }) });
      setMessage(`Export created with ${text(result.record_count)} records.`); await qc.invalidateQueries();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Export request failed."); }
  };
  const verify = async (id: string) => {
    try { const result = await apiFetch<Row>(`exports/${encodeURIComponent(id)}/verify`); setMessage(result.valid ? "Manifest and artifacts verified." : "Manifest or artifact verification failed."); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Verification failed."); }
  };
  const filtersChanged = (setter: (value: string) => void) => (value: string) => { setter(value); setOffset(0); };
  return <>
    <Heading eyebrow="Read-only evidence" heading="Audit and exports" subtitle="Investigate recorded decisions and workflow history, then verify the integrity of exported evidence."/>
    <section className="panel"><SectionTitle title="Evidence search" detail="Filters are applied by the audit API before returning scoped results"/>
      <div className="filters audit-filters"><div className="field"><label htmlFor="audit-campaign">Campaign</label><select className="select" id="audit-campaign" value={campaignId} onChange={(e) => filtersChanged(setCampaignId)(e.target.value)}><option value="">All in scope</option>{((campaigns.data?.campaigns as Row[] | undefined) ?? []).map((row) => <option key={text(row.campaign_id)} value={text(row.campaign_id)}>{text(row.name)}</option>)}</select></div><div className="field"><label htmlFor="audit-account">AWS account</label><input id="audit-account" className="input" value={accountId} onChange={(e) => filtersChanged(setAccountId)(e.target.value)} maxLength={12}/></div><div className="field"><label htmlFor="audit-principal">Principal contains</label><input id="audit-principal" className="input" value={principal} onChange={(e) => filtersChanged(setPrincipal)(e.target.value)}/></div><div className="field"><label htmlFor="audit-actor">Actor subject</label><input id="audit-actor" className="input" value={actorSub} onChange={(e) => filtersChanged(setActorSub)(e.target.value)}/></div><div className="field"><label htmlFor="audit-event-type">Event type</label><input id="audit-event-type" className="input" value={eventType} onChange={(e) => filtersChanged(setEventType)(e.target.value)} placeholder="Exact event name" maxLength={64}/></div><div className="field"><label htmlFor="audit-decision">Decision</label><select className="select" id="audit-decision" value={decision} onChange={(e) => filtersChanged(setDecision)(e.target.value)}><option value="">Any</option><option value="APPROVED">Approved</option><option value="REVOKED">Revoked</option></select></div><div className="field"><label htmlFor="audit-since">From</label><input id="audit-since" type="datetime-local" className="input" value={since} onChange={(e) => filtersChanged(setSince)(e.target.value)}/></div><div className="field"><label htmlFor="audit-until">To</label><input id="audit-until" type="datetime-local" className="input" value={until} onChange={(e) => filtersChanged(setUntil)(e.target.value)}/></div></div>
      <div className="panel-head"><div><h2>Decision and workflow timeline</h2><div className="secondary">Newest recorded events first</div></div><span className="secondary">{events.data?.total ?? 0} matching events</span></div>
      <ErrorBox error={events.error}/>
      {events.isLoading ? <div className="loading" role="status">Loading audit events…</div> : rows.length === 0 ? <EmptyState title="No events match these filters" detail="Adjust the time range, campaign, account, principal, actor, or decision."/> : <div className="panel-body"><Timeline rows={rows} empty="No events match these filters."/></div>}
      {events.data && <Pagination offset={offset} limit={Number(events.data.limit ?? PAGE_SIZE)} total={Number(events.data.total ?? 0)} hasMore={Boolean(events.data.has_more)} busy={events.isFetching} onPage={setOffset}/>}</section>
    <section className="panel export-panel"><div className="panel-head"><div><h2>Verifiable exports</h2><div className="secondary">Download artifacts and verify their manifest before use</div></div><button className="button primary" onClick={() => void createExport()}>Generate export</button></div>
      {message && <div className="notice" role="status">{message}</div>}<ErrorBox error={exports.error}/>
      <div className="table-wrap"><table><thead><tr><th>Created</th><th>Scope</th><th>Records</th><th>Manifest SHA-256</th><th>Integrity</th><th>Artifacts</th></tr></thead><tbody>{exportRows.map((row) => <tr key={text(row.export_id)}><td>{displayDate(row.created_at)}</td><td>{row.campaign_id ? `Campaign ${text(row.campaign_id)}` : "Account scope"}</td><td>{text(row.record_count)}</td><td className="mono hash-cell">{text(row.manifest_sha256)}</td><td><button className="button" onClick={() => void verify(String(row.export_id))}>Verify manifest</button></td><td><a className="button" href={`/api/backend/exports/${encodeURIComponent(String(row.export_id))}/download?artifact=csv`}>CSV</a> <a className="button" href={`/api/backend/exports/${encodeURIComponent(String(row.export_id))}/download?artifact=json`}>JSON</a></td></tr>)}</tbody></table>{exportRows.length === 0 && <EmptyState title="No exports generated" detail="Generate a scoped evidence export to create a verifiable manifest."/>}</div>
      {exports.data && <Pagination offset={exportOffset} limit={Number(exports.data.limit ?? PAGE_SIZE)} total={Number(exports.data.total ?? 0)} hasMore={Boolean(exports.data.has_more)} busy={exports.isFetching} onPage={setExportOffset}/>}</section>
  </>;
}

export function OperationsWorkspace() {
  const qc = useQueryClient();
  const [reviewId, setReviewId] = useState("");
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  const [jobOffset, setJobOffset] = useState(0);
  const [auditOffset, setAuditOffset] = useState(0);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const health = useData<Row>("ops-health", "operations/health");
  const integrations = useData<Row>("ops-integrations", "operations/integrations");
  const jobs = useData<List>("ops-jobs", `operations/jobs?limit=${PAGE_SIZE}&offset=${jobOffset}`);
  const audit = useData<List>("ops-audit", `operations/audit?limit=${PAGE_SIZE}&offset=${auditOffset}`);
  const jobRows = (jobs.data?.jobs as Row[] | undefined) ?? [];
  const eventRows = (audit.data?.events as Row[] | undefined) ?? [];
  const requestRecheck = async () => {
    try { const result = await apiFetch<Row>(`reviews/${encodeURIComponent(reviewId.trim())}/remediation/reconciliation`, { method: "POST", body: JSON.stringify({ reason: reason.trim() }) }); setMessage(`Exact-path recheck requested. Request ${text(result.request_id)}. This does not change access.`); setReason(""); setConfirmOpen(false); await qc.invalidateQueries(); }
    catch (error) { setConfirmOpen(false); setMessage(error instanceof Error ? error.message : "The request failed."); }
  };
    const aws = (integrations.data?.aws as Row | undefined) ?? {};
    const oidc = (integrations.data?.oidc as Row | undefined) ?? {};
    const genai = (integrations.data?.genai as Row | undefined) ?? {};
    const auditStorage = (integrations.data?.audit_storage as Row | undefined) ?? {};
    const remediation = (integrations.data?.remediation as Row | undefined) ?? {};
  return <>
    <Heading eyebrow="Restricted operations" heading="Platform operations" subtitle="Inspect service readiness, integration configuration, processing activity, and redacted operational events."/>
    <ErrorBox error={health.error ?? integrations.error}/>
    <section className="cards" aria-label="Service health"><MetricCard label="API service" value={<StatusBadge value={health.data?.api ?? "UNKNOWN"}/>} note="Application process health"/><MetricCard label="Database" value={<StatusBadge value={health.data?.database ?? "UNKNOWN"}/>} note="Database connectivity check"/><MetricCard label="Service status" value={<StatusBadge value={health.data?.status ?? "UNKNOWN"}/>} note="Service checks only"/><MetricCard label="AWS connectivity" value={<StatusBadge value={aws.connectivity ?? "NOT_CHECKED"}/>} note="A configured integration is not a live connection test"/></section>
    <div className="notice warning"><strong>Worker heartbeat is unavailable.</strong> Recent job rows show recorded work and do not prove a worker is currently healthy. Service health also does not prove AWS connectivity.</div>
    <section className="detail-grid"><section className="panel"><SectionTitle title="Integration readiness" detail="Configuration presence and safety gates; secrets are not displayed"/><div className="panel-body"><dl className="evidence-list">{field("AWS region configured", aws.region_configured ? "Yes" : "No")}{field("AWS credential source", aws.credential_source_configured ? "Configured" : "Not configured")}{field("AWS live connectivity", pretty(aws.connectivity))}{field("Mock discovery mode", aws.mock_mode ? "Enabled" : "Disabled")}{field("OIDC configuration", oidc.configured ? "Configured" : "Incomplete")}{field("GenAI explanations", genai.enabled ? "Enabled" : "Disabled")}{field("Audit object storage", auditStorage.s3_bucket_configured ? "Configured" : "Not configured")}{field("KMS encryption key", auditStorage.kms_key_configured ? "Configured" : "Not configured")}{field("Remediation", remediation.enabled ? (remediation.dry_run ? "Enabled in dry-run mode" : "Enabled") : "Disabled")}{field("Live remediation gate", remediation.live_gate_configured ? "Configured" : "Not configured")}</dl><p className="decision-disclaimer">Readiness reflects application configuration. Verify connectivity and credentials in your deployment environment.</p></div></section>
      <section className="panel"><SectionTitle title="Request exact-path reconciliation" detail="Read-only verification of the grant bound to a review"/><div className="panel-body"><p className="subhead">A worker will recheck the exact AWS grant path. This does not revoke access or bypass approval.</p><div className="field form-space"><label htmlFor="recheck-review">Review ID</label><input id="recheck-review" className="input" value={reviewId} onChange={(e) => setReviewId(e.target.value)}/></div><div className="field form-space"><label htmlFor="recheck-reason">Reason</label><textarea id="recheck-reason" className="textarea" maxLength={4000} value={reason} onChange={(e) => setReason(e.target.value)} /></div><button className="button primary form-space" disabled={!reviewId.trim() || !reason.trim()} onClick={() => setConfirmOpen(true)}>Review recheck request</button>{message && <div className="notice" role="status">{message}</div>}</div></section></section>
    <section className="panel operations-panel"><SectionTitle title="Discovery, AI, and remediation activity" detail="Recorded jobs in the authorized account scope" count={jobs.data?.total ?? 0}/><ErrorBox error={jobs.error}/><div className="table-wrap"><table><thead><tr><th>Activity</th><th>Started</th><th>Account</th><th>State</th><th>Outcome</th><th>Review reference</th></tr></thead><tbody>{jobRows.map((row) => <tr key={text(row.job_id)}><td><div className="principal">{pretty(row.job_type)}</div><div className="secondary mono">{text(row.job_id)}</div></td><td>{displayDate(row.started_at)}</td><td>{text(row.account_id)}</td><td><StatusBadge value={row.status}/></td><td>{row.errors ? `${text(row.errors)} errors` : text(row.error_code ?? row.source ?? "No error recorded")}</td><td className="mono">{text(row.review_id ?? "—")}</td></tr>)}</tbody></table>{jobRows.length === 0 && <EmptyState title="No processing activity recorded"/>}</div>{jobs.data && <Pagination offset={jobOffset} limit={Number(jobs.data.limit ?? PAGE_SIZE)} total={Number(jobs.data.total ?? 0)} hasMore={Boolean(jobs.data.has_more)} busy={jobs.isFetching} onPage={setJobOffset}/>}</section>
    <section className="panel operations-panel"><SectionTitle title="Operational events" detail="Sensitive event details are intentionally redacted" count={eventRows.length}/><ErrorBox error={audit.error}/><div className="table-wrap"><table><thead><tr><th>Recorded</th><th>Event</th><th>Entity</th><th>Outcome</th><th>Evidence detail</th></tr></thead><tbody>{eventRows.map((row) => <tr key={text(row.event_id)}><td>{displayDate(row.created_at)}</td><td>{pretty(row.action)}</td><td>{pretty(row.entity_type)}</td><td><StatusBadge value={row.status}/></td><td>{row.details_redacted ? "Details redacted" : "No detail available"}</td></tr>)}</tbody></table>{eventRows.length === 0 && <EmptyState title="No scoped operational events"/>}</div>{audit.data && <Pagination offset={auditOffset} limit={Number(audit.data.limit ?? PAGE_SIZE)} total={Number(audit.data.total ?? eventRows.length)} hasMore={audit.data.next_offset != null} busy={audit.isFetching} onPage={setAuditOffset}/>}</section>
    {confirmOpen && <ConfirmDialog title="Request a grant-path recheck?" summary={<><p>This asks the worker to inspect the existing evidence binding. It does not perform a destructive action.</p><dl className="evidence-list compact-evidence">{field("Review", reviewId.trim(), true)}{field("Reason", reason.trim())}</dl></>} confirmLabel="Request recheck" onCancel={() => setConfirmOpen(false)} onConfirm={() => void requestRecheck()}/>}
  </>;
}
