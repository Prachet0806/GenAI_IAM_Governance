"""Atomic publication for additional, explicitly scoped identity sources."""

import uuid
from datetime import datetime, timezone

from common import evidence, logger, repo
from common.db import db


def publish_source(
    account_id: str, source_scope: str, principals,
    *, source: str = "AWS", covered: list[str], unassessed: list[str],
):
    run_id = str(uuid.uuid4())
    started = datetime.now(timezone.utc).isoformat()
    with db.get_connection() as conn:
        repo.lock_inventory_remediation(conn)
        repo.start_discovery_attempt(conn, run_id, started, source, account_id, source_scope)
    identities = []
    observations = []
    try:
        for principal in principals:
            if not principal.get("UserId") or not principal.get("Arn"):
                raise ValueError("Principal identity is incomplete")
            identities.append(principal)
            for policy in principal.get("Policies", []):
                observations.append(
                    evidence.grant_observation(account_id, principal, policy, run_id)
                )
        missing = sum(
            item["evidence_status"] == "MISSING" for item in observations
        )
        coverage = {
            "scope_version": source_scope,
            "complete_for_declared_scope": True,
            "coverage": covered,
            "unassessed_surfaces": unassessed,
            "missing_policy_evidence": missing,
            "principal_count": len(identities),
            "grant_count": len(observations),
        }
        with db.get_connection() as conn:
            repo.lock_inventory_remediation(conn)
            published = repo.publish_discovery_snapshot(
                conn, run_id, account_id, source_scope,
                datetime.now(timezone.utc).isoformat(), identities, observations,
                coverage,
            )
        return {
            "status": "COMPLETE" if published else "INCOMPLETE",
            "snapshot_id": run_id if published else None,
            "account_id": account_id,
            "source_scope": source_scope,
            "principals_seen": len(identities),
            "grants_seen": len(observations),
            "missing_policy_evidence": missing,
        }
    except Exception as exc:
        with db.get_connection() as conn:
            repo.finish_discovery_run(
                conn, run_id, datetime.now(timezone.utc).isoformat(),
                "FAILED", len(identities), 1,
                {"error_type": type(exc).__name__, "source_scope": source_scope},
            )
        logger.log(
            "publish_source", "failed", "Source scan did not publish",
            level="ERROR", details={"run_id": run_id, "error_type": type(exc).__name__},
        )
        return {
            "status": "FAILED", "account_id": account_id,
            "source_scope": source_scope, "reason": "source_scan_failed",
        }
