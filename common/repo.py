from datetime import datetime
import json
from typing import Any, Iterable, List, Tuple

from common.db import db


# Users / roles / user_roles
def insert_user(conn, user_id: str, user_name: str, arn: str, created_at: str):
    db.execute(
        conn.cursor(),
        """
        INSERT INTO users (user_id, user_name, arn, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO NOTHING
        """,
        (user_id, user_name, arn, created_at),
    )


def insert_role(conn, role_id: str, role_name: str, risk_level: str = "LOW"):
    db.execute(
        conn.cursor(),
        """
        INSERT INTO roles (role_id, role_name, risk_level)
        VALUES (?, ?, ?)
        ON CONFLICT(role_id) DO NOTHING
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


def list_entitlements(conn) -> List[Tuple[str, str, str]]:
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


def create_review(conn, review_id: str, campaign_id: str, user_id: str, role_id: str, created_at: str):
    db.execute(
        conn.cursor(),
        """
        INSERT INTO access_reviews
        (review_id, campaign_id, user_id, role_id, status, created_at)
        VALUES (?, ?, ?, ?, 'PENDING', ?)
        """,
        (review_id, campaign_id, user_id, role_id, created_at),
    )


def list_roles(conn) -> List[Tuple[str, str, str]]:
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT role_id, role_name, risk_level
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


def list_revocations(conn) -> List[Tuple[str, str, str, str]]:
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT r.review_id, u.user_name, rol.role_name, rol.role_id
        FROM access_reviews r
        JOIN users u ON r.user_id = u.user_id
        JOIN roles rol ON r.role_id = rol.role_id
        WHERE r.status = 'REVOKED' 
        AND r.remediated_at IS NULL
        """,
    )
    return cur.fetchall()


def list_high_risk_reviews_missing_ai(conn) -> List[Tuple[str, str, str, str, str, str]]:
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT r.review_id, r.user_id, r.role_id, u.user_name, rol.role_name, rol.risk_level
        FROM access_reviews r
        JOIN users u ON r.user_id = u.user_id
        JOIN roles rol ON r.role_id = rol.role_id
        WHERE rol.risk_level = 'HIGH'
          AND (r.ai_risk_summary IS NULL OR r.ai_risk_summary = '')
        """,
    )
    return cur.fetchall()


def fetch_review_context(conn, review_id: str) -> Tuple[str, str, str, str, str, str] | None:
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


def fetch_reviews_for_export(conn) -> List[Tuple[Any, ...]]:
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
            r.remediated_at
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

