"use client";

import Link from "next/link";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api/client";
import type { ReviewQueueResponse, ReviewSummary } from "@/lib/api/types";

const PAGE_SIZE = 25;
function pretty(value: string) { return value.toLowerCase().replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }

export function ReviewerQueue() {
  const [status, setStatus] = useState("PENDING");
  const [risk, setRisk] = useState("");
  const [sortBy, setSortBy] = useState("due_date");
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const query = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE), status, sort_by: sortBy });
  if (risk) query.set("risk_level", risk);
  if (search) query.set("search", search);
  const queue = useQuery({ queryKey: ["queue", status, risk, search, sortBy, page], queryFn: () => apiFetch<ReviewQueueResponse>(`reviews/queue?${query}`) });
  const summary = useQuery({ queryKey: ["summary"], queryFn: () => apiFetch<ReviewSummary>("reviews/summary") });
  const error = queue.error instanceof Error ? queue.error.message : "The assigned queue could not be loaded.";

  function applySearch(event: React.FormEvent) { event.preventDefault(); setPage(0); setSearch(searchInput.trim()); }

  return <>
    <div className="page-heading"><div><div className="eyebrow">Reviewer workspace</div><h1>My review queue</h1><p className="subhead">Review each observed grant using its source evidence and recorded risk assessment.</p></div><div className="refresh-copy">Updates when you refresh</div></div>
    <section className="cards" aria-label="Queue summary">
      {[["Assigned", summary.data?.assigned], ["Awaiting decision", summary.data?.pending], ["High risk", summary.data?.high_risk], ["Overdue", summary.data?.overdue]].map(([label, value]) => <div className="metric" key={String(label)}><div className="metric-label">{label}</div><div className="metric-value">{summary.isLoading ? "—" : value ?? 0}</div><div className="metric-note">Your assigned campaigns</div></div>)}
    </section>
    <section className="panel">
      <div className="panel-head"><div><h2>Assigned reviews</h2><div className="secondary">{queue.data ? `${queue.data.total} matching reviews` : "Your reviewer assignment"}</div></div><button className="button" onClick={() => { void queue.refetch(); void summary.refetch(); }}>Refresh</button></div>
      <form className="filters" onSubmit={applySearch}>
        <div className="field"><label htmlFor="status">Decision status</label><select id="status" className="select" value={status} onChange={(e) => { setStatus(e.target.value); setPage(0); }}><option value="PENDING">Awaiting decision</option><option value="ALL">All assigned</option><option value="APPROVED">Approved</option><option value="REVOKED">Revoked</option></select></div>
        <div className="field"><label htmlFor="risk">Risk level</label><select id="risk" className="select" value={risk} onChange={(e) => { setRisk(e.target.value); setPage(0); }}><option value="">All levels</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option><option value="UNKNOWN">Unknown</option></select></div>
        <div className="field"><label htmlFor="sort-by">Sort reviews</label><select id="sort-by" className="select" value={sortBy} onChange={(e) => { setSortBy(e.target.value); setPage(0); }}><option value="due_date">Due date</option><option value="risk">Highest risk</option><option value="principal">Principal A to Z</option></select></div>
        <div className="field grow"><label htmlFor="search">Search principal or grant</label><input id="search" className="input" value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Name, permission, source" /></div>
        <button className="button primary" type="submit">Search</button>
      </form>
      {queue.isLoading && <div className="loading" role="status">Loading assigned reviews…</div>}
      {queue.isError && <div className="error" role="alert">{error} <button className="button" onClick={() => void queue.refetch()}>Try again</button></div>}
      {queue.data && queue.data.reviews.length === 0 && <div className="empty"><strong>No reviews match these filters.</strong><div className="secondary">Change the filters or check back when a campaign assigns work to you.</div></div>}
      {queue.data && queue.data.reviews.length > 0 && <div className="table-wrap"><table><thead><tr><th>Principal / grant</th><th>Campaign</th><th>Risk</th><th>Status</th><th>Due</th><th><span className="sr-only">Review action</span></th></tr></thead><tbody>{queue.data.reviews.map((item) => <tr key={item.review_id}>
        <td><div className="principal">{item.principal}</div><div className="secondary">{item.grant_name}</div></td>
        <td><div>{item.name}</div><div className="secondary">{item.account_id || "Account not recorded"}</div></td>
        <td><span className={`badge ${item.risk_level.toLowerCase()}`}>{pretty(item.risk_level)}</span></td>
        <td><span className={`badge ${item.status.toLowerCase()}`}>{pretty(item.status)}</span></td>
        <td>{item.due_at ? new Date(item.due_at).toLocaleDateString() : "—"}{item.due_at && new Date(item.due_at) < new Date() && item.status === "PENDING" ? <div><span className="badge overdue">Overdue</span></div> : null}</td>
        <td><Link className="row-link" href={`/reviews/${encodeURIComponent(item.review_id)}`}>{item.status === "PENDING" ? "Review →" : "View →"}</Link></td>
      </tr>)}</tbody></table></div>}
      {queue.data && <div className="pagination"><span>Showing {queue.data.total === 0 ? 0 : page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, queue.data.total)} of {queue.data.total}</span><div className="pagination-actions"><button className="button" disabled={page === 0 || queue.isFetching} onClick={() => setPage((n) => Math.max(0, n - 1))}>Previous</button><button className="button" disabled={!queue.data.has_more || queue.isFetching} onClick={() => setPage((n) => n + 1)}>Next</button></div></div>}
    </section>
  </>;
}
