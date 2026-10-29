# common/repo.py
import json
from datetime import datetime, timezone
from typing import Any

from common.db import db


# Users / roles / user_roles
def insert_user(conn, user_id: str, user_name: str, arn: str, created_at: str):
    db.execute(
        conn.cursor(),
        """
        INSERT INTO users (user_id, user_name, arn, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET user_name=excluded.user_name, arn=excluded.arn
        """,
        (user_id, user_name, arn, created_at),
    )


def insert_role(conn, role_id: str, role_name: str, risk_level: str = "LOW"):
    db.execute(
        conn.cursor(),
        """
        INSERT INTO roles (role_id, role_name, risk_level)
        VALUES (?, ?, ?)
        ON CONFLICT(role_id) DO UPDATE SET role_name=excluded.role_name
        """,
        (role_id, role_name, risk_level),
    )


def link_user_role(conn, user_id: str, role_id: str):
    db.execute(
        conn.cursor(),
        """
        INSERT INTO user_roles (user_id, role_id)
        VALUES (?, ?)
        ON CONFLICT(user_id, role_id) DO NOTHING
        """,
        (user_id, role_id),
    )


def update_role_policy(conn, role_id: str, document: dict | None, observed_at: str):
    db.execute(
        conn.cursor(),
        "UPDATE roles SET policy_document = ?, observed_at = ? WHERE role_id = ?",
        (
            json.dumps(document, sort_keys=True) if document is not None else None,
            observed_at,
            role_id,
        ),
    )


def reconcile_user_roles(conn, pairs: set[tuple[str, str]]):
    """Replace the current entitlement links only after a complete source scan."""
    conn.cursor().execute("DELETE FROM user_roles")
    if pairs:
        db.executemany(
            conn.cursor(),
            "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT(user_id, role_id) DO NOTHING",
            pairs,
        )


def start_discovery_run(conn, run_id: str, started_at: str, source: str):
    db.execute(
        conn.cursor(),
        "INSERT INTO discovery_runs (run_id, started_at, status, source) VALUES (?, ?, 'RUNNING', ?)",
        (run_id, started_at, source),
    )


def finish_discovery_run(
    conn,
    run_id: str,
    completed_at: str,
    status: str,
    users_seen: int,
    errors: int,
    details: dict | None = None,
):
    db.execute(
        conn.cursor(),
        "UPDATE discovery_runs SET completed_at=?, status=?, users_seen=?, errors=?, details=? WHERE run_id=?",
        (
            completed_at,
            status,
            users_seen,
            errors,
            json.dumps(details, default=str) if details else None,
            run_id,
        ),
    )


def latest_discovery_run(conn):
    cur = conn.cursor()
    db.execute(
        cur,
        "SELECT run_id, completed_at, status, source FROM discovery_runs ORDER BY started_at DESC, run_id DESC LIMIT 1",
    )
    return cur.fetchone()


def store_risk_assessment(
    conn,
    role_id: str,
    risk_level: str,
    reason: str,
    evidence: dict,
    rule_version: str,
    assessed_at: str,
):
    db.execute(
        conn.cursor(),
        """INSERT INTO risk_assessments (role_id,risk_level,reason,evidence,rule_version,assessed_at)
        VALUES (?,?,?,?,?,?) ON CONFLICT(role_id) DO UPDATE SET risk_level=excluded.risk_level,
        reason=excluded.reason,evidence=excluded.evidence,rule_version=excluded.rule_version,assessed_at=excluded.assessed_at""",
        (
            role_id,
            risk_level,
            reason,
            json.dumps(evidence, sort_keys=True),
            rule_version,
            assessed_at,
        ),
    )


# Campaigns / reviews
def create_campaign(conn, campaign_id: str, name: str, created_at: str):
    db.execute(
        conn.cursor(),
        """
        INSERT INTO campaigns (campaign_id, name, created_at)
        VALUES (?, ?, ?)
        """,
        (campaign_id, name, created_at),
    )


def assign_campaign_reviewer(
    conn, campaign_id: str, reviewer_sub: str, assigned_by: str
):
    cur = conn.cursor()
    db.execute(
        cur,
        """INSERT INTO campaign_reviewers (campaign_id,reviewer_sub,assigned_by)
        VALUES (?,?,?) ON CONFLICT(campaign_id,reviewer_sub) DO NOTHING""",
        (campaign_id, reviewer_sub, assigned_by),
    )
    return cur.rowcount == 1


def is_campaign_reviewer(conn, campaign_id: str, reviewer_sub: str) -> bool:
    cur = conn.cursor()
    db.execute(
        cur,
        "SELECT 1 FROM campaign_reviewers WHERE campaign_id=? AND reviewer_sub=?",
        (campaign_id, reviewer_sub),
    )
    return cur.fetchone() is not None


def fetch_review_for_decision(conn, review_id: str):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT review_id,campaign_id,status,user_id,role_id,reviewer_sub
        FROM access_reviews WHERE review_id=?""",
        (review_id,),
    )
    return cur.fetchone()


def record_remediation_approval(
    conn,
    approval_id: str,
    review_id: str,
    approver_sub: str,
    approved_at: str,
    discovery_run_id: str,
):
    cur = conn.cursor()
    db.execute(
        cur,
        """INSERT INTO remediation_approvals
        (approval_id,review_id,approver_sub,approved_at,discovery_run_id)
        VALUES (?,?,?,?,?) ON CONFLICT(review_id) DO UPDATE SET
        approval_id=excluded.approval_id,approver_sub=excluded.approver_sub,
        approved_at=excluded.approved_at,discovery_run_id=excluded.discovery_run_id
        WHERE COALESCE(remediation_approvals.discovery_run_id,'') <> excluded.discovery_run_id""",
        (approval_id, review_id, approver_sub, approved_at, discovery_run_id),
    )
    return cur.rowcount == 1


def get_remediation_approval(conn, review_id: str):
    cur = conn.cursor()
    db.execute(
        cur,
        "SELECT approver_sub,approved_at,discovery_run_id FROM remediation_approvals WHERE review_id=?",
        (review_id,),
    )
    return cur.fetchone()


def is_remediation_approved(conn, review_id: str, discovery_run_id: str) -> bool:
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT 1 FROM remediation_approvals a
        JOIN access_reviews r ON r.review_id=a.review_id
        WHERE a.review_id=? AND r.status='REVOKED' AND r.reviewer_sub IS NOT NULL
          AND a.approver_sub <> r.reviewer_sub AND a.discovery_run_id=?""",
        (review_id, discovery_run_id),
    )
    return cur.fetchone() is not None


def claim_remediation(
    conn, review_id: str, claim_token: str, now: str, lease_expires_at: str
):
    cur = conn.cursor()
    db.execute(
        cur,
        """INSERT INTO remediation_claims
        (review_id,claim_token,lease_expires_at,fencing_token)
        VALUES (?,?,?,1) ON CONFLICT(review_id) DO UPDATE SET
        claim_token=excluded.claim_token,lease_expires_at=excluded.lease_expires_at,
        fencing_token=remediation_claims.fencing_token+1
        WHERE remediation_claims.lease_expires_at <= ?""",
        (review_id, claim_token, lease_expires_at, now),
    )
    if cur.rowcount != 1:
        return None
    db.execute(
        cur,
        "SELECT fencing_token FROM remediation_claims WHERE review_id=? AND claim_token=?",
        (review_id, claim_token),
    )
    row = cur.fetchone()
    return row[0] if row else None


def renew_remediation_claim(
    conn,
    review_id: str,
    claim_token: str,
    fencing_token: int,
    now: str,
    lease_expires_at: str,
) -> bool:
    cur = conn.cursor()
    db.execute(
        cur,
        """UPDATE remediation_claims SET lease_expires_at=?
        WHERE review_id=? AND claim_token=? AND fencing_token=? AND lease_expires_at>?""",
        (lease_expires_at, review_id, claim_token, fencing_token, now),
    )
    return cur.rowcount == 1


def release_remediation_claim(
    conn, review_id: str, claim_token: str, fencing_token: int
):
    released_at = datetime.now(timezone.utc).isoformat()
    db.execute(
        conn.cursor(),
        """UPDATE remediation_claims SET lease_expires_at=?
        WHERE review_id=? AND claim_token=? AND fencing_token=?""",
        (released_at, review_id, claim_token, fencing_token),
    )


def lock_inventory_remediation(conn):
    """Serialize snapshot publication with a remediation's final check and AWS call.

    The row update holds a write lock until the surrounding transaction commits
    or rolls back on both SQLite and PostgreSQL.
    """
    db.execute(
        conn.cursor(),
        """UPDATE governance_mutex SET lock_version=lock_version+1
        WHERE lock_name='inventory_remediation'""",
    )


def is_current_entitlement(conn, review_id: str) -> bool:
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT 1 FROM access_reviews r JOIN user_roles ur
        ON ur.user_id=r.user_id AND ur.role_id=r.role_id
        WHERE r.review_id=? AND r.status='REVOKED'""",
        (review_id,),
    )
    return cur.fetchone() is not None


def campaign_exists(conn, campaign_id: str) -> bool:
    cur = conn.cursor()
    db.execute(cur, "SELECT 1 FROM campaigns WHERE campaign_id=?", (campaign_id,))
    return cur.fetchone() is not None


def list_entitlements(conn) -> list[tuple[str, str, str]]:
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT ur.user_id, ur.role_id, r.risk_level
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.role_id
        """,
    )
    return cur.fetchall()


def pending_review_exists(conn, user_id: str, role_id: str) -> bool:
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT 1 FROM access_reviews
        WHERE user_id = ? AND role_id = ? AND status = 'PENDING'
        """,
        (user_id, role_id),
    )
    return cur.fetchone() is not None


def create_review(
    conn, review_id: str, campaign_id: str, user_id: str, role_id: str, created_at: str
):
    db.execute(
        conn.cursor(),
        """
        INSERT INTO access_reviews
        (review_id, campaign_id, user_id, role_id, status, created_at)
        VALUES (?, ?, ?, ?, 'PENDING', ?)
        ON CONFLICT(review_id) DO NOTHING
        """,
        (review_id, campaign_id, user_id, role_id, created_at),
    )


def create_review_if_pending(
    conn, review_id: str, campaign_id: str, user_id: str, role_id: str, created_at: str
) -> bool:
    """Race-safe insert; unique constraints arbitrate concurrent campaign runs."""
    cur = conn.cursor()
    db.execute(
        cur,
        """INSERT INTO access_reviews
        (review_id,campaign_id,user_id,role_id,status,created_at)
        VALUES (?,?,?,?,'PENDING',?) ON CONFLICT DO NOTHING""",
        (review_id, campaign_id, user_id, role_id, created_at),
    )
    return cur.rowcount == 1


def list_roles(conn) -> list[tuple[str, str, str, str | None]]:
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT role_id, role_name, risk_level, policy_document
        FROM roles
        """,
    )
    return cur.fetchall()


def update_role_risk(conn, role_id: str, new_risk: str):
    db.execute(
        conn.cursor(),
        """
        UPDATE roles
        SET risk_level = ?
        WHERE role_id = ?
        """,
        (new_risk, role_id),
    )


def list_revocations(conn) -> list[tuple[str, str, str, str]]:
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT r.review_id, u.user_name, rol.role_name, rol.role_id
        FROM access_reviews r
        JOIN users u ON r.user_id = u.user_id
        JOIN roles rol ON r.role_id = rol.role_id
        JOIN user_roles ur ON ur.user_id = r.user_id AND ur.role_id = r.role_id
        WHERE r.status = 'REVOKED' 
        AND r.remediated_at IS NULL
        """,
    )
    return cur.fetchall()


def list_high_risk_reviews_missing_ai(
    conn,
) -> list[tuple[str, str, str, str, str, str]]:
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT r.review_id, r.user_id, r.role_id, u.user_name, rol.role_name, rol.risk_level
        FROM access_reviews r
        JOIN users u ON r.user_id = u.user_id
        JOIN roles rol ON r.role_id = rol.role_id
        WHERE rol.risk_level = 'HIGH' AND r.status = 'PENDING'
          AND (r.ai_risk_summary IS NULL OR r.ai_risk_summary = '')
        """,
    )
    return cur.fetchall()


def fetch_review_context(
    conn, review_id: str
) -> tuple[str, str, str, str, str, str] | None:
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT r.review_id, r.user_id, r.role_id, u.user_name, rol.role_name, rol.risk_level
        FROM access_reviews r
        JOIN users u ON r.user_id = u.user_id
        JOIN roles rol ON r.role_id = rol.role_id
        WHERE r.review_id = ?
        """,
        (review_id,),
    )
    return cur.fetchone()


def fetch_review_ai_context(conn, review_id: str):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT r.review_id,r.status,r.user_id,r.role_id,u.user_name,rol.role_name,rol.risk_level,
        rol.policy_document,ra.reason,ra.evidence,ra.rule_version
        FROM access_reviews r JOIN users u ON u.user_id=r.user_id JOIN roles rol ON rol.role_id=r.role_id
        LEFT JOIN risk_assessments ra ON ra.role_id=rol.role_id WHERE r.review_id=?""",
        (review_id,),
    )
    return cur.fetchone()


def record_ai_generation(
    conn,
    generation_id: str,
    review_id: str,
    source: str,
    status: str,
    model: str | None,
    prompt_version: str,
    input_hash: str,
    output_hash: str,
    summary: str,
    created_at: str,
):
    db.execute(
        conn.cursor(),
        """INSERT INTO ai_generations
        (generation_id,review_id,source,status,model,prompt_version,input_sha256,output_sha256,summary,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            generation_id,
            review_id,
            source,
            status,
            model,
            prompt_version,
            input_hash,
            output_hash,
            summary,
            created_at,
        ),
    )


def mark_remediated(conn, review_id: str, ts: str):
    db.execute(
        conn.cursor(),
        """
        UPDATE access_reviews
        SET remediated_at = ?
        WHERE review_id = ?
        """,
        (ts, review_id),
    )


def fetch_reviews_for_export(conn) -> list[tuple[Any, ...]]:
    """Stable export row with latest append-only AI provenance fields at the end."""
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT 
            r.review_id,
            r.campaign_id,
            u.user_name,
            rol.role_name,
            rol.risk_level,
            r.status,
            r.reviewer_comment,
            r.ai_risk_summary,
            r.created_at,
            r.reviewed_at,
            r.remediated_at,
            (SELECT source FROM ai_generations g WHERE g.review_id=r.review_id ORDER BY created_at DESC LIMIT 1),
            (SELECT model FROM ai_generations g WHERE g.review_id=r.review_id ORDER BY created_at DESC LIMIT 1),
            (SELECT prompt_version FROM ai_generations g WHERE g.review_id=r.review_id ORDER BY created_at DESC LIMIT 1),
            (SELECT created_at FROM ai_generations g WHERE g.review_id=r.review_id ORDER BY created_at DESC LIMIT 1)
        FROM access_reviews r
        JOIN users u ON r.user_id = u.user_id
        JOIN roles rol ON r.role_id = rol.role_id
        ORDER BY r.created_at DESC
        """,
    )
    return cur.fetchall()


def insert_audit_log(
    conn,
    log_id: str,
    timestamp: datetime,
    level: str,
    action: str,
    status: str,
    message: str,
    entity_type: str | None = None,
    entity_id: str | None = None,
    details: dict | None = None,
):
    db.execute(
        conn.cursor(),
        """
        INSERT INTO audit_logs
            (id, timestamp, level, action, entity_type, entity_id, status, message, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            log_id,
            timestamp.isoformat(),
            level,
            action,
            entity_type,
            entity_id,
            status,
            message,
            json.dumps(details, default=str) if details else None,
        ),
    )
