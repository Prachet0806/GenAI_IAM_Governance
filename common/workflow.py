"""Campaign lifecycle, reviewer queues, and append-only workflow history."""

import json
import uuid
from datetime import datetime, timezone

from common.db import db


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_dict(cursor, row):
    return dict(zip((column[0] for column in cursor.description), row)) if row else None


def campaign(conn, campaign_id: str, *, lock: bool = False):
    cur = conn.cursor()
    suffix = " FOR UPDATE" if lock and not db._is_sqlite_now() else ""
    db.execute(
        cur,
        """SELECT campaign_id,name,snapshot_id,account_id,source_scope,owner_sub,
                  due_at,state,closed_at,created_at FROM campaigns WHERE campaign_id=?"""
        + suffix,
        (campaign_id,),
    )
    result = _row_dict(cur, cur.fetchone())
    if result:
        for key in ("due_at", "closed_at", "created_at"):
            if result[key] is not None:
                result[key] = str(result[key])
    return result


def review_workflow(conn, review_id: str):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT r.review_id,r.campaign_id,r.status,r.assigned_reviewer_sub,
                  r.due_at,r.exception_state,c.state AS campaign_state
           FROM access_reviews r JOIN campaigns c ON c.campaign_id=r.campaign_id
           WHERE r.review_id=?""",
        (review_id,),
    )
    result = _row_dict(cur, cur.fetchone())
    if result and result["due_at"] is not None:
        result["due_at"] = str(result["due_at"])
    return result


def record_event(
    conn, campaign_id: str, event_type: str, actor_sub: str,
    *, review_id: str | None = None, previous=None, new=None, details=None,
):
    db.execute(
        conn.cursor(),
        """INSERT INTO review_workflow_events
           (event_id,campaign_id,review_id,event_type,actor_sub,previous_value,
            new_value,details,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            str(uuid.uuid4()), campaign_id, review_id, event_type, actor_sub,
            previous, new, json.dumps(details or {}, sort_keys=True), _stamp(),
        ),
    )


def queue(conn, reviewer_sub: str, *, limit: int = 100, offset: int = 0):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT r.review_id,r.campaign_id,r.status,r.assigned_reviewer_sub,
                  r.due_at,r.exception_state,c.state,c.name,c.account_id,
                  c.source_scope,
                  CASE WHEN r.observation_id IS NULL THEN rol.risk_level
                       ELSE gra.risk_level END AS risk_level
           FROM access_reviews r
           JOIN campaigns c ON c.campaign_id=r.campaign_id
           JOIN campaign_reviewers cr ON cr.campaign_id=r.campaign_id
           JOIN roles rol ON rol.role_id=r.role_id
           LEFT JOIN grant_risk_assessments gra
             ON gra.assessment_id=r.risk_assessment_id
           WHERE cr.reviewer_sub=? AND r.status='PENDING' AND c.state='OPEN'
             AND (r.assigned_reviewer_sub IS NULL OR r.assigned_reviewer_sub=?)
           ORDER BY CASE WHEN r.due_at IS NULL THEN 1 ELSE 0 END,
                    r.due_at,r.created_at,r.review_id LIMIT ? OFFSET ?""",
        (reviewer_sub, reviewer_sub, limit, offset),
    )
    rows = [_row_dict(cur, row) for row in cur.fetchall()]
    for row in rows:
        if row["due_at"] is not None:
            row["due_at"] = str(row["due_at"])
    return rows


def events(conn, campaign_id: str, *, limit: int = 100, offset: int = 0):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT event_id,campaign_id,review_id,event_type,actor_sub,
                  previous_value,new_value,details,created_at
           FROM review_workflow_events WHERE campaign_id=?
           ORDER BY created_at DESC,event_id DESC LIMIT ? OFFSET ?""",
        (campaign_id, limit, offset),
    )
    rows = [_row_dict(cur, row) for row in cur.fetchall()]
    for row in rows:
        row["details"] = json.loads(row["details"])
        row["created_at"] = str(row["created_at"])
    return rows


def assign_review(conn, review_id: str, reviewer_sub: str, actor_sub: str):
    review = review_workflow(conn, review_id)
    if not review:
        return "not_found"
    campaign_id = review["campaign_id"]
    campaign_row = campaign(conn, campaign_id, lock=True)
    if campaign_row["state"] != "OPEN" or review["status"] != "PENDING":
        return "not_open"
    cur = conn.cursor()
    db.execute(
        cur,
        "SELECT 1 FROM campaign_reviewers WHERE campaign_id=? AND reviewer_sub=?",
        (campaign_id, reviewer_sub),
    )
    if not cur.fetchone():
        return "not_in_pool"
    previous = review["assigned_reviewer_sub"]
    if previous == reviewer_sub:
        return "unchanged"
    db.execute(
        cur,
        """UPDATE access_reviews SET assigned_reviewer_sub=?
           WHERE review_id=? AND status='PENDING'
             AND (assigned_reviewer_sub=? OR
                  (assigned_reviewer_sub IS NULL AND ? IS NULL))""",
        (reviewer_sub, review_id, previous, previous),
    )
    if cur.rowcount != 1:
        return "conflict"
    record_event(
        conn, campaign_id,
        "REVIEW_REASSIGNED" if previous else "REVIEW_ASSIGNED",
        actor_sub, review_id=review_id, previous=previous, new=reviewer_sub,
    )
    return "assigned"


def set_exception(conn, review_id: str, target: str, actor_sub: str, reason: str):
    review = review_workflow(conn, review_id)
    if not review:
        return "not_found"
    campaign_row = campaign(conn, review["campaign_id"], lock=True)
    if review["status"] != "PENDING" or campaign_row["state"] == "CLOSED":
        return "not_open"
    expected = "NONE" if target == "OPEN" else "OPEN"
    if review["exception_state"] != expected:
        return "invalid_transition"
    cur = conn.cursor()
    db.execute(
        cur,
        """UPDATE access_reviews SET exception_state=?
           WHERE review_id=? AND status='PENDING' AND exception_state=?""",
        (target, review_id, expected),
    )
    if cur.rowcount != 1:
        return "conflict"
    record_event(
        conn, review["campaign_id"],
        "EXCEPTION_OPENED" if target == "OPEN" else "EXCEPTION_RESOLVED",
        actor_sub, review_id=review_id, previous=expected, new=target,
        details={"reason": reason},
    )
    return "updated"


def change_campaign_state(conn, campaign_id: str, target: str, actor_sub: str):
    item = campaign(conn, campaign_id, lock=True)
    if not item:
        return "not_found"
    current = item["state"]
    if target not in {"OPEN", "PAUSED", "CLOSED"} or (
        current, target
    ) not in {("OPEN", "PAUSED"), ("PAUSED", "OPEN"),
              ("OPEN", "CLOSED"), ("PAUSED", "CLOSED")}:
        return "invalid_transition"
    if target == "CLOSED":
        cur = conn.cursor()
        db.execute(
            cur,
            """SELECT 1 FROM access_reviews WHERE campaign_id=?
               AND (status='PENDING' OR exception_state='OPEN') LIMIT 1""",
            (campaign_id,),
        )
        if cur.fetchone():
            return "incomplete"
    cur = conn.cursor()
    db.execute(
        cur,
        "UPDATE campaigns SET state=?,closed_at=? WHERE campaign_id=? AND state=?",
        (target, _stamp() if target == "CLOSED" else None, campaign_id, current),
    )
    if cur.rowcount != 1:
        return "conflict"
    record_event(
        conn, campaign_id, "CAMPAIGN_STATE_CHANGED", actor_sub,
        previous=current, new=target,
    )
    return "updated"


def change_campaign_field(conn, campaign_id: str, field: str, value: str, actor_sub: str):
    if field not in {"owner_sub", "due_at"}:
        raise ValueError("Unsupported campaign field")
    item = campaign(conn, campaign_id, lock=True)
    if not item:
        return "not_found"
    if item["state"] == "CLOSED":
        return "not_open"
    previous = item[field]
    if previous == value:
        return "unchanged"
    cur = conn.cursor()
    db.execute(
        cur,
        f"UPDATE campaigns SET {field}=? WHERE campaign_id=? AND state<>'CLOSED'",
        (value, campaign_id),
    )
    if cur.rowcount != 1:
        return "conflict"
    record_event(
        conn, campaign_id,
        "CAMPAIGN_OWNER_CHANGED" if field == "owner_sub" else "CAMPAIGN_DEADLINE_CHANGED",
        actor_sub, previous=previous, new=value,
    )
    return "updated"


def change_review_deadline(conn, review_id: str, value: str, actor_sub: str):
    review = review_workflow(conn, review_id)
    if not review:
        return "not_found"
    item = campaign(conn, review["campaign_id"], lock=True)
    review = review_workflow(conn, review_id)
    if item["state"] == "CLOSED" or review["status"] != "PENDING":
        return "not_open"
    previous = review["due_at"]
    if previous == value:
        return "unchanged"
    cur = conn.cursor()
    db.execute(
        cur, """UPDATE access_reviews SET due_at=?
             WHERE review_id=? AND status='PENDING'
               AND (due_at=? OR (due_at IS NULL AND ? IS NULL))""",
        (value, review_id, previous, previous),
    )
    if cur.rowcount != 1:
        return "conflict"
    record_event(
        conn, review["campaign_id"], "REVIEW_DEADLINE_CHANGED", actor_sub,
        review_id=review_id, previous=previous, new=value,
    )
    return "updated"
