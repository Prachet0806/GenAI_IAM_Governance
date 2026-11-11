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
                  r.due_at,r.exception_state,c.state AS campaign_state,c.account_id
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


def _queue_filter_sql(
    *, status: str | None, risk_level: str | None, campaign_id: str | None,
    account_id: str | None, principal: str | None, search: str | None,
    due_before: str | None,
    account_scopes: list[str] | None,
):
    risk_sql = "CASE WHEN r.observation_id IS NULL THEN rol.risk_level ELSE gra.risk_level END"
    clauses = [
        "cr.reviewer_sub=?",
        "(r.assigned_reviewer_sub IS NULL OR r.assigned_reviewer_sub=?)",
    ]
    values: list = []
    if status:
        clauses.append("r.status=?")
        values.append(status)
    if risk_level:
        clauses.append(f"{risk_sql}=?")
        values.append(risk_level)
    if campaign_id:
        clauses.append("r.campaign_id=?")
        values.append(campaign_id)
    if account_id:
        clauses.append("c.account_id=?")
        values.append(account_id)
    if principal:
        clauses.append("LOWER(COALESCE(go.principal_name,u.user_name)) LIKE ?")
        values.append(f"%{principal.lower()}%")
    if search:
        clauses.append(
            "(LOWER(COALESCE(go.principal_name,u.user_name)) LIKE ? "
            "OR LOWER(COALESCE(go.policy_name,rol.role_name)) LIKE ? "
            "OR LOWER(c.name) LIKE ?)"
        )
        values.extend([f"%{search.lower()}%"] * 3)
    if due_before:
        clauses.append("r.due_at IS NOT NULL AND r.due_at<=?")
        values.append(due_before)
    if account_scopes is not None:
        if not account_scopes:
            clauses.append("1=0")
        elif "*" not in account_scopes:
            clauses.append("c.account_id IN (" + ",".join("?" for _ in account_scopes) + ")")
            values.extend(account_scopes)
    return " AND ".join(clauses), values


def queue(
    conn, reviewer_sub: str, *, limit: int = 100, offset: int = 0,
    status: str | None = "PENDING", risk_level: str | None = None,
    campaign_id: str | None = None, account_id: str | None = None,
    principal: str | None = None, search: str | None = None,
    due_before: str | None = None,
    sort_by: str = "due_date",
    account_scopes: list[str] | None = None,
):
    cur = conn.cursor()
    where, filters = _queue_filter_sql(
        status=status, risk_level=risk_level, campaign_id=campaign_id,
        account_id=account_id, principal=principal, search=search,
        due_before=due_before,
        account_scopes=account_scopes,
    )
    risk_sql = "CASE WHEN r.observation_id IS NULL THEN rol.risk_level ELSE gra.risk_level END"
    principal_sql = "LOWER(COALESCE(go.principal_name,u.user_name))"
    order_by = {
        "due_date": "CASE WHEN r.due_at IS NULL THEN 1 ELSE 0 END,r.due_at",
        "risk": f"CASE {risk_sql} WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 WHEN 'LOW' THEN 2 ELSE 3 END,CASE WHEN r.due_at IS NULL THEN 1 ELSE 0 END,r.due_at",
        "principal": f"{principal_sql},CASE WHEN r.due_at IS NULL THEN 1 ELSE 0 END,r.due_at",
    }[sort_by]
    db.execute(
        cur,
        f"""SELECT r.review_id,r.campaign_id,r.status,r.assigned_reviewer_sub,
                  r.due_at,r.exception_state,c.state,c.name,c.account_id,
                  c.source_scope,r.snapshot_id,
                  COALESCE(go.principal_name,u.user_name) AS principal,
                  COALESCE(go.policy_name,rol.role_name) AS grant_name,
                  gp.grant_type,go.source_name,
                  {risk_sql} AS risk_level
           FROM access_reviews r
           JOIN campaigns c ON c.campaign_id=r.campaign_id
           JOIN campaign_reviewers cr ON cr.campaign_id=r.campaign_id
           JOIN roles rol ON rol.role_id=r.role_id
           JOIN users u ON u.user_id=r.user_id
           LEFT JOIN grant_paths gp ON gp.grant_id=r.grant_id
           LEFT JOIN grant_observations go ON go.observation_id=r.observation_id
           LEFT JOIN grant_risk_assessments gra
             ON gra.assessment_id=r.risk_assessment_id
           WHERE {where}
           ORDER BY {order_by},r.created_at,r.review_id LIMIT ? OFFSET ?""",
        [reviewer_sub, reviewer_sub, *filters, limit, offset],
    )
    rows = [_row_dict(cur, row) for row in cur.fetchall()]
    for row in rows:
        if row["due_at"] is not None:
            row["due_at"] = str(row["due_at"])
    return rows


def queue_total(
    conn, reviewer_sub: str, *, status: str | None = "PENDING",
    risk_level: str | None = None, campaign_id: str | None = None,
    account_id: str | None = None, principal: str | None = None,
    search: str | None = None,
    due_before: str | None = None, account_scopes: list[str] | None = None,
) -> int:
    cur = conn.cursor()
    where, filters = _queue_filter_sql(
        status=status, risk_level=risk_level, campaign_id=campaign_id,
        account_id=account_id, principal=principal, search=search,
        due_before=due_before,
        account_scopes=account_scopes,
    )
    db.execute(
        cur,
        f"""SELECT COUNT(*) FROM access_reviews r
            JOIN campaigns c ON c.campaign_id=r.campaign_id
            JOIN campaign_reviewers cr ON cr.campaign_id=r.campaign_id
            JOIN roles rol ON rol.role_id=r.role_id
            JOIN users u ON u.user_id=r.user_id
            LEFT JOIN grant_paths gp ON gp.grant_id=r.grant_id
            LEFT JOIN grant_observations go ON go.observation_id=r.observation_id
            LEFT JOIN grant_risk_assessments gra
              ON gra.assessment_id=r.risk_assessment_id
            WHERE {where}""",
        [reviewer_sub, reviewer_sub, *filters],
    )
    return int(cur.fetchone()[0])


def queue_summary(conn, reviewer_sub: str, *, account_scopes: list[str] | None = None) -> dict:
    cur = conn.cursor()
    clauses = [
        "cr.reviewer_sub=?",
        "(r.assigned_reviewer_sub IS NULL OR r.assigned_reviewer_sub=?)",
    ]
    values: list = [reviewer_sub, reviewer_sub]
    if account_scopes is not None:
        if not account_scopes:
            clauses.append("1=0")
        elif "*" not in account_scopes:
            clauses.append("c.account_id IN (" + ",".join("?" for _ in account_scopes) + ")")
            values.extend(account_scopes)
    risk_sql = "CASE WHEN r.observation_id IS NULL THEN rol.risk_level ELSE gra.risk_level END"
    db.execute(
        cur,
        f"""SELECT r.status,{risk_sql},r.due_at FROM access_reviews r
            JOIN campaigns c ON c.campaign_id=r.campaign_id
            JOIN campaign_reviewers cr ON cr.campaign_id=r.campaign_id
            JOIN roles rol ON rol.role_id=r.role_id
            LEFT JOIN grant_risk_assessments gra
              ON gra.assessment_id=r.risk_assessment_id
            WHERE {' AND '.join(clauses)}""",
        values,
    )
    rows = cur.fetchall()
    now = _stamp()
    result = {
        "assigned": len(rows), "pending": 0, "approved": 0, "revoked": 0,
        "high_risk": 0, "overdue": 0,
    }
    for status, risk_level, due_at in rows:
        result[status.lower()] = result.get(status.lower(), 0) + 1
        if risk_level == "HIGH":
            result["high_risk"] += 1
        if status == "PENDING" and due_at is not None and str(due_at) < now:
            result["overdue"] += 1
    return result


def review_history(conn, review_id: str) -> list[dict]:
    """Combine immutable decision and assignment/workflow events for one review."""
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT event_id,decision,reviewer_sub,reviewer_comment,decided_at,
                  snapshot_id,grant_id,observation_id,risk_assessment_id,
                  decision_origin
           FROM review_decision_events WHERE review_id=?""",
        (review_id,),
    )
    decisions = [
        {
            "event_id": row[0], "event_type": "REVIEW_DECISION",
            "decision": row[1], "actor_sub": row[2], "comment": row[3],
            "created_at": str(row[4]), "snapshot_id": row[5],
            "grant_id": row[6], "observation_id": row[7],
            "risk_assessment_id": row[8], "decision_origin": row[9],
        }
        for row in cur.fetchall()
    ]
    db.execute(
        cur,
        """SELECT event_id,event_type,actor_sub,previous_value,new_value,
                  details,created_at
           FROM review_workflow_events WHERE review_id=?""",
        (review_id,),
    )
    workflow_events = [
        {
            "event_id": row[0], "event_type": row[1], "actor_sub": row[2],
            "previous_value": row[3], "new_value": row[4],
            "details": json.loads(row[5]), "created_at": str(row[6]),
        }
        for row in cur.fetchall()
    ]
    return sorted(decisions + workflow_events, key=lambda item: (item["created_at"], item["event_id"]))


def events(conn, campaign_id: str, *, limit: int = 100, offset: int = 0):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT event_id,campaign_id,review_id,event_type,actor_sub,
                  previous_value,new_value,details,created_at
           FROM review_workflow_events WHERE campaign_id=?
           ORDER BY created_at DESC,event_id DESC LIMIT ?""",
        (campaign_id, limit + offset),
    )
    rows = [_row_dict(cur, row) for row in cur.fetchall()]
    for row in rows:
        row["details"] = json.loads(row["details"])
        row["created_at"] = str(row["created_at"])
    db.execute(cur, """SELECT event_id,campaign_id,NULL AS review_id,
        'CAMPAIGN_REVIEWER_' || event_type AS event_type,actor_sub,
        NULL AS previous_value,reviewer_sub AS new_value,'{}' AS details,created_at
        FROM campaign_reviewer_events WHERE campaign_id=?
        ORDER BY created_at DESC,event_id DESC LIMIT ?""",
        (campaign_id, limit + offset))
    membership = [_row_dict(cur, row) for row in cur.fetchall()]
    for row in membership:
        row["details"] = {"reviewer_sub": row["new_value"]}
        row["created_at"] = str(row["created_at"])
    combined = sorted(rows + membership, key=lambda item: (item["created_at"], item["event_id"]), reverse=True)
    return combined[offset:offset + limit]


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
