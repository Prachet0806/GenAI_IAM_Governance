"""Read models for the campaign, remediation, audit, and operations workspaces."""

import json
from datetime import datetime, timezone

from common import config, evidence, repo
from common.db import db


def _scope_filter(column: str, scopes: list[str] | None, values: list):
    if scopes is None or "*" in scopes:
        return None
    if not scopes:
        return "1=0"
    values.extend(scopes)
    return f"{column} IN ({','.join('?' for _ in scopes)})"


def campaigns(conn, scopes: list[str] | None, *, limit=50, offset=0, state=None):
    cur = conn.cursor()
    values: list = []
    clauses = []
    scope_sql = _scope_filter("c.account_id", scopes, values)
    if scope_sql:
        clauses.append(scope_sql)
    if state:
        clauses.append("c.state=?")
        values.append(state)
    where = " AND ".join(clauses) if clauses else "1=1"
    db.execute(cur, f"""SELECT c.campaign_id,c.name,c.created_at,c.account_id,
        c.source_scope,c.snapshot_id,c.owner_sub,c.due_at,c.state,c.closed_at,
        COUNT(r.review_id),
        SUM(CASE WHEN r.status='PENDING' THEN 1 ELSE 0 END),
        SUM(CASE WHEN r.status='APPROVED' THEN 1 ELSE 0 END),
        SUM(CASE WHEN r.status='REVOKED' THEN 1 ELSE 0 END),
        SUM(CASE WHEN r.exception_state='OPEN' THEN 1 ELSE 0 END),
        SUM(CASE WHEN r.status='PENDING' AND r.due_at IS NOT NULL
                      AND r.due_at<? THEN 1 ELSE 0 END)
        FROM campaigns c LEFT JOIN access_reviews r ON r.campaign_id=c.campaign_id
        WHERE {where} GROUP BY c.campaign_id
        ORDER BY c.created_at DESC,c.campaign_id LIMIT ? OFFSET ?""",
        [datetime.now(timezone.utc).isoformat(), *values, limit, offset])
    rows = cur.fetchall()
    items = [{
        "campaign_id": row[0], "name": row[1], "created_at": str(row[2]),
        "account_id": row[3], "source_scope": row[4], "snapshot_id": row[5],
        "owner_sub": row[6], "due_at": str(row[7]) if row[7] else None,
        "state": row[8], "closed_at": str(row[9]) if row[9] else None,
        "total_reviews": int(row[10] or 0), "pending": int(row[11] or 0),
        "approved": int(row[12] or 0), "revoked": int(row[13] or 0),
        "open_exceptions": int(row[14] or 0), "overdue": int(row[15] or 0),
    } for row in rows]
    db.execute(cur, f"SELECT COUNT(*) FROM campaigns c WHERE {where}", values)
    total = int(cur.fetchone()[0])
    return {"campaigns": items, "limit": limit, "offset": offset,
            "total": total, "has_more": offset + len(items) < total}


def campaign_reviewers(conn, campaign_id: str):
    cur = conn.cursor()
    db.execute(cur, """SELECT cr.reviewer_sub,cr.assigned_at,cr.assigned_by,
        COUNT(r.review_id),
        SUM(CASE WHEN r.status='PENDING' THEN 1 ELSE 0 END),
        SUM(CASE WHEN r.status IN ('APPROVED','REVOKED') THEN 1 ELSE 0 END)
        FROM campaign_reviewers cr LEFT JOIN access_reviews r
          ON r.campaign_id=cr.campaign_id
         AND r.assigned_reviewer_sub=cr.reviewer_sub
        WHERE cr.campaign_id=? GROUP BY cr.reviewer_sub,cr.assigned_at,cr.assigned_by
        ORDER BY cr.assigned_at,cr.reviewer_sub""", (campaign_id,))
    return [{"reviewer_sub": row[0], "assigned_at": str(row[1]),
             "assigned_by": row[2], "assigned": int(row[3] or 0),
             "pending": int(row[4] or 0), "completed": int(row[5] or 0)}
            for row in cur.fetchall()]


def campaign_progress(conn, campaign_id: str):
    cur = conn.cursor()
    db.execute(cur, """SELECT r.status,
        CASE WHEN r.observation_id IS NULL THEN rol.risk_level ELSE gra.risk_level END,
        r.due_at,r.exception_state FROM access_reviews r
        JOIN roles rol ON rol.role_id=r.role_id
        LEFT JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id
        WHERE r.campaign_id=?""", (campaign_id,))
    rows = cur.fetchall()
    now = datetime.now(timezone.utc).isoformat()
    result = {"total": len(rows), "pending": 0, "approved": 0, "revoked": 0,
              "high_risk": 0, "medium_risk": 0, "low_risk": 0,
              "unknown_risk": 0, "overdue": 0, "open_exceptions": 0}
    for status, risk, due, exception in rows:
        result[status.lower()] += 1
        result[f"{(risk or 'UNKNOWN').lower()}_risk"] += 1
        if status == "PENDING" and due and str(due) < now:
            result["overdue"] += 1
        if exception == "OPEN":
            result["open_exceptions"] += 1
    result["completed"] = result["approved"] + result["revoked"]
    result["completion_percent"] = round(100 * result["completed"] / result["total"], 1) if result["total"] else 0
    result["reviewers"] = campaign_reviewers(conn, campaign_id)
    return result


def campaign_reviews(conn, campaign_id: str, *, limit=100, offset=0, status=None):
    cur = conn.cursor()
    clauses = ["r.campaign_id=?"]
    values: list = [campaign_id]
    if status:
        clauses.append("r.status=?")
        values.append(status)
    where = " AND ".join(clauses)
    query = f"""SELECT r.review_id,r.status,r.assigned_reviewer_sub,r.due_at,
        r.exception_state,r.user_id,r.role_id,
        COALESCE(go.principal_name,u.user_name),COALESCE(go.policy_name,rol.role_name),
        CASE WHEN r.observation_id IS NULL THEN rol.risk_level ELSE gra.risk_level END,
        r.snapshot_id,ps.account_id
        FROM access_reviews r JOIN users u ON u.user_id=r.user_id
        JOIN roles rol ON rol.role_id=r.role_id
        LEFT JOIN grant_observations go ON go.observation_id=r.observation_id
        LEFT JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id
        LEFT JOIN published_snapshots ps ON ps.snapshot_id=r.snapshot_id
        WHERE {where} ORDER BY CASE WHEN r.due_at IS NULL THEN 1 ELSE 0 END,
        r.due_at,r.created_at,r.review_id LIMIT ? OFFSET ?"""
    db.execute(cur, query, [*values, limit, offset])
    rows = cur.fetchall()
    db.execute(cur, f"SELECT COUNT(*) FROM access_reviews r WHERE {where}", values)
    total = int(cur.fetchone()[0])
    items = [{
        "review_id": row[0], "status": row[1], "assigned_reviewer_sub": row[2],
        "due_at": str(row[3]) if row[3] else None, "exception_state": row[4],
        "user_id": row[5], "role_id": row[6], "principal": row[7],
        "grant_name": row[8], "risk_level": row[9], "snapshot_id": row[10],
        "account_id": row[11],
    } for row in rows]
    return {"reviews": items, "limit": limit, "offset": offset,
            "total": total, "has_more": offset + len(items) < total}


def snapshot_candidates(conn, scopes: list[str] | None, *, account_id=None, limit=100, offset=0):
    cur = conn.cursor()
    values: list = []
    clauses = []
    scope_sql = _scope_filter("s.account_id", scopes, values)
    if scope_sql:
        clauses.append(scope_sql)
    if account_id:
        clauses.append("s.account_id=?")
        values.append(account_id)
    where = " AND ".join(clauses) if clauses else "1=1"
    db.execute(cur, f"""SELECT s.snapshot_id,s.account_id,s.source_scope,s.published_at,
        s.users_seen,s.coverage,d.status,d.source,d.started_at,d.completed_at,
        d.errors,h.attempt_id,p.snapshot_id,hd.status
        FROM published_snapshots s JOIN discovery_runs d ON d.run_id=s.snapshot_id
        LEFT JOIN source_attempt_heads h ON h.account_id=s.account_id AND h.source_scope=s.source_scope
        LEFT JOIN discovery_runs hd ON hd.run_id=h.attempt_id
        LEFT JOIN source_publications p ON p.account_id=s.account_id AND p.source_scope=s.source_scope
        WHERE {where} ORDER BY s.published_at DESC,s.snapshot_id LIMIT ? OFFSET ?""",
        [*values, limit, offset])
    rows = cur.fetchall()
    items = []
    for row in rows:
        coverage = json.loads(row[5]) if row[5] else {}
        current = row[0] == row[12]
        latest = row[11] == row[0]
        eligible = repo.eligible_published_snapshot(conn, row[1], row[2])
        items.append({
            "snapshot_id": row[0], "account_id": row[1], "source_scope": row[2],
            "published_at": str(row[3]), "users_seen": row[4], "coverage": coverage,
            "discovery_status": row[6], "discovery_source": row[7],
            "started_at": str(row[8]) if row[8] else None,
            "completed_at": str(row[9]) if row[9] else None, "errors": row[10],
            "latest_attempt_id": row[11], "latest_attempt_status": row[13],
            "is_current_publication": current,
            "eligible_for_campaign": bool(eligible and eligible["snapshot_id"] == row[0]),
        })
    db.execute(cur, f"SELECT COUNT(*) FROM published_snapshots s WHERE {where}", values)
    total = int(cur.fetchone()[0])
    return {"snapshots": items, "limit": limit, "offset": offset, "total": total,
            "has_more": offset + len(items) < total}


def snapshot_readiness(conn, snapshot_id: str, scopes: list[str] | None):
    cur = conn.cursor()
    values: list = [snapshot_id]
    clauses = ["s.snapshot_id=?"]
    scope_sql = _scope_filter("s.account_id", scopes, values)
    if scope_sql:
        clauses.append(scope_sql)
    db.execute(cur, f"""SELECT s.snapshot_id,s.account_id,s.source_scope,s.published_at,
        s.users_seen,s.coverage,d.status,d.source,d.errors,h.attempt_id,p.snapshot_id,hd.status
        FROM published_snapshots s JOIN discovery_runs d ON d.run_id=s.snapshot_id
        LEFT JOIN source_attempt_heads h ON h.account_id=s.account_id AND h.source_scope=s.source_scope
        LEFT JOIN discovery_runs hd ON hd.run_id=h.attempt_id
        LEFT JOIN source_publications p ON p.account_id=s.account_id AND p.source_scope=s.source_scope
        WHERE {' AND '.join(clauses)}""", values)
    row = cur.fetchone()
    if not row:
        return None
    coverage = json.loads(row[5]) if row[5] else {}
    blockers = []
    if row[6] != "COMPLETE":
        blockers.append({"code": "DISCOVERY_INCOMPLETE", "message": "The published discovery run is not complete."})
    if row[10] != snapshot_id:
        blockers.append({"code": "NOT_CURRENT_PUBLICATION", "message": "A different snapshot is currently published for this account and source."})
    if row[9] != snapshot_id or row[11] != "COMPLETE":
        blockers.append({"code": "NEWER_DISCOVERY_ATTEMPT", "message": "A newer discovery attempt must complete before this snapshot can be used."})
    if not coverage.get("complete_for_declared_scope"):
        blockers.append({"code": "COVERAGE_INCOMPLETE", "message": "The snapshot does not declare complete coverage for its source scope."})
    eligible = repo.eligible_published_snapshot(conn, row[1], row[2])
    if not eligible or eligible["snapshot_id"] != snapshot_id:
        if not any(blocker["code"] == "NEWER_DISCOVERY_ATTEMPT" for blocker in blockers):
            blockers.append({"code": "SNAPSHOT_NOT_ELIGIBLE", "message": "The snapshot fails freshness or publication eligibility checks."})
    risk_complete = repo.snapshot_risk_complete(conn, snapshot_id, evidence.POLICY_RULE_VERSION)
    if not risk_complete:
        blockers.append({"code": "RISK_ASSESSMENT_INCOMPLETE", "message": "Risk assessment is not complete for every grant in this snapshot."})
    grant_count = len(repo.list_assessed_grants(conn, snapshot_id, evidence.POLICY_RULE_VERSION)) if risk_complete else 0
    if risk_complete and grant_count == 0:
        blockers.append({"code": "NO_REVIEWABLE_GRANTS", "message": "No assessed grant paths are available for certification."})
    active = repo.active_campaign_for_snapshot(conn, snapshot_id)
    if active:
        blockers.append({"code": "ACTIVE_CAMPAIGN_EXISTS", "message": "An open or paused campaign already uses this snapshot."})
    return {
        "snapshot_id": row[0], "account_id": row[1], "source_scope": row[2],
        "published_at": str(row[3]), "users_seen": row[4], "coverage": coverage,
        "discovery_status": row[6], "discovery_source": row[7], "errors": row[8],
        "latest_attempt_id": row[9], "published_snapshot_id": row[10],
        "latest_attempt_status": row[11],
        "risk_assessment_complete": risk_complete, "reviewable_grants": grant_count,
        "existing_campaign_id": active, "eligible_for_campaign": not blockers,
        "blockers": blockers,
    }


def remediation_eligibility(conn, review_id: str, approver_sub: str):
    cur = conn.cursor()
    db.execute(cur, """SELECT r.status,r.reviewer_sub,r.snapshot_id,r.grant_id,
        r.observation_id,r.risk_assessment_id,r.campaign_id,
        CASE WHEN r.observation_id IS NULL THEN u.user_name ELSE go.principal_name END,
        CASE WHEN r.observation_id IS NULL THEN rol.role_name ELSE go.policy_name END,
        CASE WHEN r.observation_id IS NULL THEN rol.risk_level ELSE gra.risk_level END,
        c.account_id,c.source_scope,c.name,r.reviewer_comment
        FROM access_reviews r JOIN campaigns c ON c.campaign_id=r.campaign_id
        JOIN users u ON u.user_id=r.user_id JOIN roles rol ON rol.role_id=r.role_id
        LEFT JOIN grant_observations go ON go.observation_id=r.observation_id
        LEFT JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id
        WHERE r.review_id=?""", (review_id,))
    row = cur.fetchone()
    if not row:
        return None
    blockers = []
    if row[0] != "REVOKED":
        blockers.append({"code": "REVIEW_NOT_REVOKED", "message": "Only a recorded revoke decision can enter remediation approval."})
    if not row[1]:
        blockers.append({"code": "REVIEWER_IDENTITY_MISSING", "message": "The original reviewer identity is not verified."})
    elif row[1] == approver_sub:
        blockers.append({"code": "SELF_APPROVAL", "message": "The reviewer cannot approve or decline their own remediation."})
    decision_event = repo.authenticated_revocation_event(conn, review_id)
    if not decision_event:
        blockers.append({"code": "AUTHENTICATED_REVOCATION_REQUIRED", "message": "A snapshot-bound decision from the authenticated review workflow is required."})
    binding = repo.review_evidence_binding(conn, review_id)
    if not binding:
        blockers.append({"code": "EVIDENCE_NOT_PINNED", "message": "Complete snapshot-pinned grant evidence is required."})
    else:
        if binding["grant_type"] not in repo.REMEDIATION_ACTIONS:
            blockers.append({"code": "UNSUPPORTED_GRANT_TYPE", "message": "This grant type is not supported by the remediation worker."})
        if binding["evidence_status"] != "COMPLETE" or not binding["principal_arn"]:
            blockers.append({"code": "INCOMPLETE_EVIDENCE", "message": "Complete principal and grant evidence is required."})
        current = repo.eligible_published_snapshot(conn, binding["account_id"], binding["source_scope"], require_aws=True)
        if not current or current["snapshot_id"] != binding["snapshot_id"]:
            blockers.append({"code": "SNAPSHOT_NOT_CURRENT", "message": "The bound AWS snapshot is no longer eligible."})
        if not repo.is_current_grant_for_review(conn, review_id):
            blockers.append({"code": "GRANT_NOT_CURRENT", "message": "The exact observed grant is no longer current or cannot be verified."})
    approval = repo.get_remediation_approval(conn, review_id)
    if approval:
        blockers.append({"code": "ALREADY_APPROVED", "message": "An independent approval already exists for this discovery run."})
    decline = repo.remediation_decline(conn, review_id)
    if decline:
        blockers.append({"code": "ALREADY_DECLINED", "message": "This remediation request has already been declined."})
    history = repo.remediation_history(conn, review_id)
    existing_action = bool(history["action_events"])
    return {
        "review_id": review_id, "campaign_id": row[6], "campaign_name": row[12],
        "account_id": row[10], "source_scope": row[11], "principal": row[7],
        "grant_name": row[8], "risk_level": row[9], "status": row[0],
        "reviewer_sub": row[1], "reviewer_comment": row[13],
        "snapshot_id": binding["snapshot_id"] if binding else row[2],
        "grant_id": binding["grant_id"] if binding else row[3],
        "observation_id": binding["observation_id"] if binding else row[4],
        "risk_assessment_id": binding["risk_assessment_id"] if binding else row[5],
        "grant_type": binding["grant_type"] if binding else None,
        "action_type": repo.REMEDIATION_ACTIONS.get(binding["grant_type"]) if binding else None,
        "principal_arn": binding["principal_arn"] if binding else None,
        "eligible": not blockers, "blockers": blockers,
        "approval": {"approver_sub": approval[0], "approved_at": str(approval[1]),
                     "discovery_run_id": approval[2]} if approval else None,
        "execution_state": (history["action_events"][-1]["event_type"] if existing_action else "NOT_STARTED"),
        "history": history,
    }


def remediation_queue(conn, scopes: list[str] | None, approver_sub: str,
                      *, limit=50, offset=0):
    cur = conn.cursor()
    values: list = []
    scope_sql = _scope_filter("c.account_id", scopes, values)
    clauses = ["r.status='REVOKED'"]
    if scope_sql:
        clauses.append(scope_sql)
    db.execute(cur, f"""SELECT r.review_id FROM access_reviews r
        JOIN campaigns c ON c.campaign_id=r.campaign_id
        WHERE {' AND '.join(clauses)} ORDER BY r.reviewed_at DESC,r.review_id""", values)
    ids = [row[0] for row in cur.fetchall()]
    items = []
    for review_id in ids:
        item = remediation_eligibility(conn, review_id, approver_sub)
        if not item:
            continue
        if item["approval"]:
            state = item["execution_state"] if item["execution_state"] != "NOT_STARTED" else "APPROVED"
        elif repo.remediation_decline(conn, review_id):
            state = "DECLINED"
        else:
            state = "AWAITING_APPROVAL"
        item["workflow_state"] = state
        item.pop("history", None)
        items.append(item)
    return {"items": items[offset:offset + limit], "limit": limit, "offset": offset,
            "total": len(items), "has_more": offset + limit < len(items)}


def audit_events(conn, scopes: list[str] | None, *, limit=100, offset=0,
                 campaign_id=None, account_id=None, review_id=None,
                 principal=None, actor_sub=None, decision=None,
                 remediation_status=None, since=None, until=None):
    from common import workflow

    cur = conn.cursor()
    values: list = []
    clauses = []
    scope_sql = _scope_filter("c.account_id", scopes, values)
    if scope_sql:
        clauses.append(scope_sql)
    if account_id:
        clauses.append("c.account_id=?")
        values.append(account_id)
    if campaign_id:
        clauses.append("c.campaign_id=?")
        values.append(campaign_id)
    where = " AND ".join(clauses) if clauses else "1=1"
    db.execute(cur, f"SELECT c.campaign_id FROM campaigns c WHERE {where}", values)
    campaign_ids = [row[0] for row in cur.fetchall()]
    events = []
    for current_campaign in campaign_ids:
        campaign_events = workflow.events(conn, current_campaign, limit=1000, offset=0)
        if not principal and not review_id:
            for event in campaign_events:
                events.append({
                    "event_id": event["event_id"], "campaign_id": current_campaign,
                    "review_id": event.get("review_id"), "event_type": event["event_type"],
                    "actor_sub": event["actor_sub"], "created_at": event["created_at"],
                    "summary": event["event_type"].replace("_", " ").title(),
                    "details": event.get("details", {}),
                })
        review_values: list = [current_campaign]
        review_clauses = ["r.campaign_id=?"]
        if review_id:
            review_clauses.append("r.review_id=?")
            review_values.append(review_id)
        if principal:
            review_clauses.append("LOWER(COALESCE(go.principal_name,u.user_name)) LIKE ?")
            review_values.append(f"%{principal.lower()}%")
        db.execute(cur, f"""SELECT r.review_id FROM access_reviews r
            JOIN users u ON u.user_id=r.user_id
            LEFT JOIN grant_observations go ON go.observation_id=r.observation_id
            WHERE {' AND '.join(review_clauses)}""", review_values)
        for (current_review,) in cur.fetchall():
            for event in workflow.review_history(conn, current_review):
                events.append({
                    "event_id": event["event_id"], "campaign_id": current_campaign,
                    "review_id": current_review, "event_type": event["event_type"],
                    "actor_sub": event.get("actor_sub"), "created_at": event["created_at"],
                    "decision": event.get("decision"), "summary": event.get("decision") or event["event_type"].replace("_", " ").title(),
                    "details": {key: value for key, value in event.items() if key not in {"event_id", "event_type", "actor_sub", "created_at"}},
                })
            remediation = repo.remediation_history(conn, current_review)
            for kind, key in (("APPROVAL", "approval_events"), ("ACTION", "action_events"), ("RECONCILIATION", "reconciliation_events")):
                for event in remediation[key]:
                    events.append({
                        "event_id": event["event_id"], "campaign_id": current_campaign,
                        "review_id": current_review, "event_type": f"REMEDIATION_{kind}_{event['event_type']}",
                        "actor_sub": event.get("approver_sub") or event.get("actor_id"),
                        "created_at": str(event.get("approved_at") or event.get("created_at")),
                        "summary": event["event_type"].replace("_", " ").title(),
                        "details": {key: value for key, value in event.items() if key not in {"event_id", "event_type"}},
                    })
    if actor_sub:
        events = [event for event in events if event.get("actor_sub") == actor_sub]
    if decision:
        events = [event for event in events if event.get("decision") == decision]
    if remediation_status:
        events = [event for event in events if remediation_status in event["event_type"]]
    if since:
        events = [event for event in events if event["created_at"] >= since]
    if until:
        events = [event for event in events if event["created_at"] <= until]
    events.sort(key=lambda event: (event["created_at"], event["event_id"]), reverse=True)
    return {"events": events[offset:offset + limit], "limit": limit, "offset": offset,
            "total": len(events), "has_more": offset + limit < len(events)}

