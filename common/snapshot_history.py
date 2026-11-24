"""Bounded, account-scoped read models for source attempts and snapshot changes."""

import json

from common import evidence_manifest, repo
from common.db import db

MAX_COMPARE_OBSERVATIONS = 10_000
_CHANGE_FIELDS = (
    "principal_name", "principal_arn", "source_name", "policy_name",
    "policy_version", "policy_sha256", "evidence_status", "missing_reason",
)


class ComparisonTooLarge(ValueError):
    """The pair of source snapshots exceeds the interactive comparison bound."""


def _scope_clause(column: str, scopes: list[str] | None, values: list) -> str:
    if scopes is None or "*" in scopes:
        return "1=1"
    if not scopes:
        return "1=0"
    values.extend(scopes)
    return f"{column} IN ({','.join('?' for _ in scopes)})"


def list_attempts(
    conn, scopes: list[str] | None, *, account_id: str | None = None,
    source_scope: str | None = None, limit: int = 50, offset: int = 0,
) -> dict:
    values: list = []
    clauses = ["d.account_id IS NOT NULL", _scope_clause("d.account_id", scopes, values)]
    if account_id:
        clauses.append("d.account_id=?")
        values.append(account_id)
    if source_scope:
        clauses.append("d.source_scope=?")
        values.append(source_scope)
    where = " AND ".join(clauses)
    cur = conn.cursor()
    db.execute(cur, f"SELECT COUNT(*) FROM discovery_runs d WHERE {where}", values)
    total = int(cur.fetchone()[0])
    db.execute(
        cur,
        f"""SELECT d.run_id,d.account_id,d.source_scope,d.started_at,d.completed_at,
                   d.status,d.source,d.users_seen,d.errors,d.details,
                   r.collected_at,r.principal_count,r.grant_count,
                   r.missing_document_count,r.coverage
            FROM discovery_runs d LEFT JOIN collection_receipts r ON r.run_id=d.run_id
            WHERE {where} ORDER BY d.started_at DESC,d.run_id DESC LIMIT ? OFFSET ?""",
        [*values, limit, offset],
    )
    items = []
    for row in cur.fetchall():
        outcome = repo.discovery_attempt_outcome(conn, row[0])
        items.append({
            "attempt_id": row[0], "account_id": row[1], "source_scope": row[2],
            "started_at": str(row[3]),
            "completed_at": str(row[4]) if row[4] else None,
            "run_status": row[5], "source": row[6], "users_seen": row[7],
            "errors": row[8], "details": json.loads(row[9]) if row[9] else None,
            "collected_at": str(row[10]) if row[10] else None,
            "principal_count": row[11], "grant_count": row[12],
            "missing_document_count": row[13],
            "coverage": json.loads(row[14]) if row[14] else None,
            **outcome,
        })
    return {
        "attempts": items, "limit": limit, "offset": offset, "total": total,
        "has_more": offset + len(items) < total,
    }


def snapshot_metadata(conn, snapshot_id: str, scopes: list[str] | None) -> dict | None:
    values: list = [snapshot_id]
    scope = _scope_clause("s.account_id", scopes, values)
    cur = conn.cursor()
    db.execute(
        cur,
        f"""SELECT s.account_id,s.source_scope,s.published_at,s.coverage
            FROM published_snapshots s
            WHERE s.snapshot_id=? AND {scope}""",
        values,
    )
    row = cur.fetchone()
    if not row:
        return None
    manifest = evidence_manifest.source_manifest(conn, snapshot_id)
    return {
        "snapshot_id": snapshot_id, "account_id": row[0],
        "source_scope": row[1], "published_at": str(row[2]),
        "coverage": json.loads(row[3]),
        "manifest_sha256": manifest["sha256"],
        "observation_window": manifest["manifest"]["snapshots"][0]["observation_window"],
        "invalidations": repo.list_evidence_invalidations(conn, snapshot_id),
    }


def _observations(conn, snapshot_id: str) -> dict[str, dict]:
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT go.grant_id,go.observation_id,gp.grant_type,gp.source_id,
                  gp.attachment_id,go.principal_name,go.principal_arn,
                  go.source_name,go.policy_name,go.policy_version,
                  go.policy_sha256,go.evidence_status,go.missing_reason,
                  go.observed_at
           FROM grant_observations go JOIN grant_paths gp ON gp.grant_id=go.grant_id
           WHERE go.snapshot_id=? ORDER BY go.grant_id LIMIT ?""",
        (snapshot_id, MAX_COMPARE_OBSERVATIONS + 1),
    )
    rows = cur.fetchall()
    if len(rows) > MAX_COMPARE_OBSERVATIONS:
        raise ComparisonTooLarge("Source snapshot exceeds interactive comparison limit")
    return {
        row[0]: {
            "grant_id": row[0], "observation_id": row[1],
            "grant_type": row[2], "source_id": row[3],
            "attachment_id": row[4], "principal_name": row[5],
            "principal_arn": row[6], "source_name": row[7],
            "policy_name": row[8], "policy_version": row[9],
            "policy_sha256": row[10], "evidence_status": row[11],
            "missing_reason": row[12], "observed_at": str(row[13]),
        }
        for row in rows
    }


def compare_snapshots(
    conn, before_id: str, after_id: str, scopes: list[str] | None,
    *, limit: int = 100, offset: int = 0,
) -> dict | None:
    before = snapshot_metadata(conn, before_id, scopes)
    after = snapshot_metadata(conn, after_id, scopes)
    if before is None or after is None:
        return None
    if (before["account_id"], before["source_scope"]) != (
        after["account_id"], after["source_scope"]
    ):
        raise ValueError("Snapshots must share an account and declared source scope")
    old = _observations(conn, before_id)
    new = _observations(conn, after_id)
    counts = {"added": 0, "removed": 0, "changed": 0, "unchanged": 0}
    changes = []
    for grant_id in sorted(old.keys() | new.keys()):
        prior, current = old.get(grant_id), new.get(grant_id)
        fields = [key for key in _CHANGE_FIELDS if prior and current and prior[key] != current[key]]
        if prior is None:
            kind = "added"
        elif current is None:
            kind = "removed"
        elif fields:
            kind = "changed"
        else:
            kind = "unchanged"
        counts[kind] += 1
        if kind != "unchanged":
            changes.append({
                "kind": kind.upper(), "grant_id": grant_id,
                "changed_fields": fields, "before": prior, "after": current,
            })
    page = changes[offset:offset + limit]
    return {
        "before": before, "after": after,
        "counts": counts, "changes": page,
        "limit": limit, "offset": offset, "total": len(changes),
        "has_more": offset + len(page) < len(changes),
        "comparison_scope": "OBSERVED_GRANT_PATHS_ONLY",
        "effective_access_evaluated": False,
    }
