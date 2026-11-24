"""Canonical Phase 0 manifests projected from immutable published evidence."""

import hashlib
import json
from datetime import datetime, timezone

from common import evidence, repo
from common.db import db

SCHEMA_VERSION = "evidence-manifest-v1"


def _utc(value):
    if value is None:
        return None
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(
        str(value).replace("Z", "+00:00")
    )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def canonical_hash(manifest: dict) -> str:
    return hashlib.sha256(evidence.canonical_json(manifest).encode("utf-8")).hexdigest()


def _coverage(value):
    result = json.loads(value) if isinstance(value, str) else dict(value)
    for key in ("coverage", "unassessed_surfaces"):
        if key in result:
            result[key] = sorted(set(result[key]))
    return result


def source_manifest(conn, snapshot_id: str) -> dict | None:
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT account_id,source_scope,published_at,coverage
           FROM published_snapshots WHERE snapshot_id=?""",
        (snapshot_id,),
    )
    snapshot = cur.fetchone()
    if snapshot is None:
        return None
    account_id, source_scope, published_at, coverage = snapshot
    db.execute(
        cur,
        """SELECT go.observation_id,go.grant_id,gp.source_id,gp.attachment_id,
                  go.policy_version,go.policy_sha256,go.observed_at,
                  go.evidence_status,go.missing_reason
           FROM grant_observations go
           JOIN grant_paths gp ON gp.grant_id=go.grant_id
           WHERE go.snapshot_id=? ORDER BY go.observation_id""",
        (snapshot_id,),
    )
    references = [
        {
            "observation_id": row[0], "grant_id": row[1],
            "source_id": row[2], "attachment_id": row[3],
            "policy_version": row[4], "policy_sha256": row[5],
            "observed_at": _utc(row[6]), "evidence_status": row[7],
            "missing_reason": row[8],
        }
        for row in cur.fetchall()
    ]
    observed = [item["observed_at"] for item in references if item["observed_at"]]
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": "SINGLE_SOURCE",
        "account_id": account_id,
        "source_scope": source_scope,
        "snapshots": [{
            "snapshot_id": snapshot_id,
            "published_at": _utc(published_at),
            "observation_window": {
                "start": min(observed) if observed else None,
                "end": max(observed) if observed else None,
            },
            "coverage": _coverage(coverage),
            "evidence": references,
        }],
    }
    return {"manifest": body, "sha256": canonical_hash(body)}


def review_manifest(conn, review_id: str, *, source: dict | None = None) -> dict | None:
    binding = repo.review_evidence_binding(conn, review_id)
    if binding is None:
        return None
    if source is None:
        source = source_manifest(conn, binding["snapshot_id"])
    if source is None:
        return None
    if source["manifest"]["snapshots"][0]["snapshot_id"] != binding["snapshot_id"]:
        raise ValueError("Review and source manifests refer to different snapshots")
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT gra.policy_assessment_id,gra.rule_version
           FROM grant_risk_assessments gra WHERE gra.assessment_id=?""",
        (binding["risk_assessment_id"],),
    )
    assessment = cur.fetchone()
    if assessment is None:
        return None
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": "REVIEW",
        "review_id": review_id,
        "source_manifest_sha256": source["sha256"],
        "account_id": binding["account_id"],
        "source_scope": binding["source_scope"],
        "snapshot_id": binding["snapshot_id"],
        "grant_id": binding["grant_id"],
        "observation_id": binding["observation_id"],
        "grant_assessment_id": binding["risk_assessment_id"],
        "policy_assessment_id": assessment[0],
        "rule_version": assessment[1],
        "source_id": binding["source_id"],
        "attachment_id": binding["attachment_id"],
        "policy_version": binding["policy_version"],
        "policy_sha256": binding["policy_sha256"],
        "evidence_status": binding["evidence_status"],
    }
    return {"manifest": body, "sha256": canonical_hash(body)}
