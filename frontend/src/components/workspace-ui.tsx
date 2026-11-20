"use client";

import { useEffect, useRef, useState } from "react";

export function pretty(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not recorded";
  return String(value).toLowerCase().replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function displayDate(value: unknown, includeTime = true): string {
  if (typeof value !== "string" || !value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, includeTime
    ? { dateStyle: "medium", timeStyle: "short" }
    : { dateStyle: "medium" }).format(date);
}

export function StatusBadge({ value }: { value: unknown }) {
  const text = pretty(value);
  const tone = String(value ?? "").toLowerCase();
  const statusClass = /high|revoked|overdue|failed|declined|blocked|error|reconciliation_required/.test(tone)
    ? "danger"
    : /medium|pending|awaiting|running|paused|open/.test(tone)
      ? "warning"
      : /approved|complete|verified|ready|healthy|success|closed|low/.test(tone)
        ? "success" : "neutral";
  return <span className={`status-badge ${statusClass}`}>{text}</span>;
}

export function MetricCard({ label, value, note }: { label: string; value: React.ReactNode; note?: string }) {
  return <div className="metric"><div className="metric-label">{label}</div><div className="metric-value">{value}</div>{note && <div className="metric-note">{note}</div>}</div>;
}

export function Pagination({ offset, limit, total, hasMore, busy, onPage }: {
  offset: number; limit: number; total: number; hasMore: boolean; busy?: boolean; onPage: (nextOffset: number) => void;
}) {
  const first = total === 0 ? 0 : offset + 1;
  const last = Math.min(offset + limit, total);
  return <div className="pagination" aria-label="Result pages">
    <span>Showing {first}–{last} of {total}</span>
    <div className="pagination-actions">
      <button className="button" disabled={offset === 0 || busy} onClick={() => onPage(Math.max(0, offset - limit))}>Previous</button>
      <button className="button" disabled={!hasMore || busy} onClick={() => onPage(offset + limit)}>Next</button>
    </div>
  </div>;
}

export function ConfirmDialog({ title, summary, confirmLabel, danger, busy, onConfirm, onCancel }: {
  title: string; summary: React.ReactNode; confirmLabel: string; danger?: boolean; busy?: boolean; onConfirm: () => void; onCancel: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [confirming, setConfirming] = useState(false);
  useEffect(() => {
    const element = dialog.current;
    if (element && !element.open) {
      if (typeof element.showModal === "function") element.showModal();
      else element.setAttribute("open", "");
    }
    return () => { if (element?.open && typeof element.close === "function") element.close(); };
  }, []);
  return <dialog className="confirm-dialog" ref={dialog} aria-labelledby="confirm-title" onCancel={(event) => { event.preventDefault(); onCancel(); }}>
    <div className="confirm-content">
      <div className="eyebrow">Confirm governance action</div>
      <h2 id="confirm-title">{title}</h2>
      <div className="confirm-summary">{summary}</div>
      <div className="decision-actions">
        <button className="button" disabled={busy || confirming} onClick={onCancel}>Go back</button>
        <button className={`button ${danger ? "danger" : "primary"}`} disabled={busy || confirming} onClick={async () => { setConfirming(true); try { await onConfirm(); } finally { setConfirming(false); } }}>{busy || confirming ? "Saving…" : confirmLabel}</button>
      </div>
    </div>
  </dialog>;
}

export function EmptyState({ title, detail }: { title: string; detail?: string }) {
  return <div className="empty-state"><span className="evidence-mark" aria-hidden="true"/><strong>{title}</strong>{detail && <span>{detail}</span>}</div>;
}
