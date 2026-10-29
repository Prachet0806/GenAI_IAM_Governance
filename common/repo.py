# common/repo.py
import json
from datetime import datetime, timezone
from typing import Any

from common import config, evidence
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


def start_discovery_attempt(
    conn, run_id: str, started_at: str, mode: str, account_id: str, source_scope: str
):
    """Advance only this source's attempt head; keep its publication intact."""
    db.execute(
        conn.cursor(),
        """INSERT INTO discovery_runs
        (run_id,started_at,status,source,account_id,source_scope)
        VALUES (?,?,'RUNNING',?,?,?)""",
        (run_id, started_at, f"{mode}:{source_scope}", account_id, source_scope),
    )
    db.execute(
        conn.cursor(),
        """INSERT INTO source_attempt_heads(account_id,source_scope,attempt_id)
        VALUES (?,?,?) ON CONFLICT(account_id,source_scope)
        DO UPDATE SET attempt_id=excluded.attempt_id""",
        (account_id, source_scope, run_id),
    )


def source_attempt_head(conn, account_id: str, source_scope: str):
    cur = conn.cursor()
    db.execute(
        cur,
        "SELECT attempt_id FROM source_attempt_heads WHERE account_id=? AND source_scope=?",
        (account_id, source_scope),
    )
    row = cur.fetchone()
    return row[0] if row else None


def published_snapshot(conn, account_id: str, source_scope: str):
    """Return the last successful publication even if a newer scan failed."""
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT p.snapshot_id,s.published_at,d.status,d.source,s.coverage,s.users_seen
        FROM source_publications p
        JOIN published_snapshots s ON s.snapshot_id=p.snapshot_id
        JOIN discovery_runs d ON d.run_id=s.snapshot_id
        WHERE p.account_id=? AND p.source_scope=?
          AND s.account_id=p.account_id AND s.source_scope=p.source_scope""",
        (account_id, source_scope),
    )
    return cur.fetchone()


def eligible_published_snapshot(
    conn,
    account_id: str | None = None,
    source_scope: str = evidence.IAM_USER_POLICY_SCOPE,
    require_aws: bool = False,
):
    """Require a fresh complete publication with no newer unresolved attempt."""
    if account_id is None:
        cur = conn.cursor()
        db.execute(
            cur,
            "SELECT account_id FROM source_publications WHERE source_scope=?",
            (source_scope,),
        )
        accounts = [row[0] for row in cur.fetchall()]
        if len(accounts) != 1:
            return None
        account_id = accounts[0]
    row = published_snapshot(conn, account_id, source_scope)
    if not row or row[2] != "COMPLETE":
        return None
    if require_aws and row[3] != f"AWS:{source_scope}":
        return None
    if source_attempt_head(conn, account_id, source_scope) != row[0]:
        return None
    try:
        coverage = json.loads(row[4])
        if not coverage.get("complete_for_declared_scope"):
            return None
        published_at = row[1]
        if not isinstance(published_at, datetime):
            published_at = datetime.fromisoformat(
                str(published_at).replace("Z", "+00:00")
            )
        if published_at.tzinfo is None:
            published_at = published_at.replace(tzinfo=timezone.utc)
        age_hours = (
            datetime.now(timezone.utc) - published_at.astimezone(timezone.utc)
        ).total_seconds() / 3600
        if not (-0.1 <= age_hours <= config.get_max_discovery_age_hours()):
            return None
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None
    return {
        "snapshot_id": row[0],
        "account_id": account_id,
        "source_scope": source_scope,
        "published_at": row[1],
    }


def publish_discovery_snapshot(
    conn,
    run_id: str,
    account_id: str,
    source_scope: str,
    completed_at: str,
    users: list[dict],
    observations: list[dict],
    coverage: dict,
) -> bool:
    """Publish one complete source view atomically with its observations."""
    if source_attempt_head(conn, account_id, source_scope) != run_id:
        finish_discovery_run(
            conn,
            run_id,
            completed_at,
            "INCOMPLETE",
            len(users),
            0,
            {"snapshot_published": False, "reason": "superseded"},
        )
        return False
    db.execute(
        conn.cursor(),
        """INSERT INTO published_snapshots
        (snapshot_id,account_id,source_scope,published_at,users_seen,coverage)
        VALUES (?,?,?,?,?,?)""",
        (run_id, account_id, source_scope, completed_at, len(users), json.dumps(coverage, sort_keys=True)),
    )
    for user in users:
        insert_user(
            conn,
            user["UserId"],
            user["UserName"],
            user["Arn"],
            user["CreateDate"].isoformat(),
        )
    for item in observations:
        insert_role(conn, item["policy_id"], item["policy_name"], "LOW")
        update_role_policy(
            conn, item["policy_id"], json.loads(item["policy_document"]), item["observed_at"]
        )
        db.execute(
            conn.cursor(),
            """INSERT INTO grant_paths
            (grant_id,account_id,principal_id,principal_arn,grant_type,source_id,attachment_id,policy_id)
            VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(grant_id) DO NOTHING""",
            (
                item["grant_id"], account_id, item["principal_id"], item["principal_arn"],
                item["grant_type"], item["source_id"], item["attachment_id"], item["policy_id"],
            ),
        )
        db.execute(
            conn.cursor(),
            """INSERT INTO grant_observations
            (observation_id,snapshot_id,grant_id,principal_name,source_name,
             policy_name,policy_version,policy_sha256,policy_document,observed_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                item["observation_id"], run_id, item["grant_id"], item["principal_name"],
                item["source_name"], item["policy_name"], item["policy_version"],
                item["policy_sha256"], item["policy_document"], item["observed_at"],
            ),
        )
    db.execute(
        conn.cursor(),
        """INSERT INTO source_publications(account_id,source_scope,snapshot_id)
        VALUES (?,?,?) ON CONFLICT(account_id,source_scope)
        DO UPDATE SET snapshot_id=excluded.snapshot_id""",
        (account_id, source_scope, run_id),
    )
    # Legacy user_roles remains a projection of all currently published sources.
    conn.cursor().execute("DELETE FROM user_roles")
    conn.cursor().execute(
        """INSERT INTO user_roles(user_id,role_id)
        SELECT DISTINCT gp.principal_id,gp.policy_id
        FROM source_publications sp
        JOIN grant_observations go ON go.snapshot_id=sp.snapshot_id
        JOIN grant_paths gp ON gp.grant_id=go.grant_id"""
    )
    finish_discovery_run(
        conn, run_id, completed_at, "COMPLETE", len(users), 0, coverage
    )
    return True


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


def list_current_observations(conn, snapshot_id: str | None = None):
    cur = conn.cursor()
    where = "WHERE go.snapshot_id=?" if snapshot_id else ""
    db.execute(
        cur,
        f"""SELECT go.observation_id,go.snapshot_id,go.grant_id,gp.policy_id,
        go.policy_name,go.policy_document,go.policy_sha256,gp.account_id,
        gp.principal_id,gp.grant_type,go.source_name
        FROM source_publications sp
        JOIN grant_observations go ON go.snapshot_id=sp.snapshot_id
        JOIN grant_paths gp ON gp.grant_id=go.grant_id
        {where}
        ORDER BY go.snapshot_id,go.grant_id""",
        (snapshot_id,) if snapshot_id else (),
    )
    return cur.fetchall()


def store_snapshot_risk(
    conn,
    observation,
    risk_level: str,
    reason: str,
    risk_evidence: dict,
    rule_version: str,
    assessed_at: str,
):
    observation_id, snapshot_id, _grant_id, policy_id, _name, _document, policy_hash = observation[:7]
    policy_id_key = evidence.stable_id(
        "policy-risk", snapshot_id, policy_id, policy_hash, rule_version
    )
    grant_id_key = evidence.stable_id("grant-risk", observation_id, rule_version)
    evidence_json = evidence.canonical_json(risk_evidence)
    db.execute(
        conn.cursor(),
        """INSERT INTO policy_risk_assessments
        (assessment_id,snapshot_id,policy_id,policy_sha256,rule_version,risk_level,
         reason,evidence,assessed_at)
        VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(assessment_id) DO NOTHING""",
        (
            policy_id_key, snapshot_id, policy_id, policy_hash, rule_version,
            risk_level, reason, evidence_json, assessed_at,
        ),
    )
    cur = conn.cursor()
    db.execute(
        cur,
        "SELECT risk_level,reason,evidence FROM policy_risk_assessments WHERE assessment_id=?",
        (policy_id_key,),
    )
    if cur.fetchone() != (risk_level, reason, evidence_json):
        raise RuntimeError("Existing policy risk assessment differs for this rule version")
    db.execute(
        conn.cursor(),
        """INSERT INTO grant_risk_assessments
        (assessment_id,observation_id,policy_assessment_id,rule_version,
         risk_level,reason,assessed_at)
        VALUES (?,?,?,?,?,?,?) ON CONFLICT(assessment_id) DO NOTHING""",
        (
            grant_id_key, observation_id, policy_id_key, rule_version,
            risk_level, "Policy risk applied to this grant path; not effective access",
            assessed_at,
        ),
    )
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT policy_assessment_id,risk_level,reason
        FROM grant_risk_assessments WHERE assessment_id=?""",
        (grant_id_key,),
    )
    if cur.fetchone() != (
        policy_id_key,
        risk_level,
        "Policy risk applied to this grant path; not effective access",
    ):
        raise RuntimeError("Existing grant risk assessment differs for this rule version")
    return grant_id_key


def snapshot_risk_complete(conn, snapshot_id: str, rule_version: str) -> bool:
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT COUNT(*),COUNT(gra.assessment_id)
        FROM grant_observations go
        LEFT JOIN grant_risk_assessments gra
          ON gra.observation_id=go.observation_id AND gra.rule_version=?
        LEFT JOIN policy_risk_assessments pra
          ON pra.assessment_id=gra.policy_assessment_id
         AND pra.snapshot_id=go.snapshot_id AND pra.policy_sha256=go.policy_sha256
        WHERE go.snapshot_id=? AND
          (gra.assessment_id IS NULL OR pra.assessment_id IS NULL
           OR gra.risk_level<>pra.risk_level)""",
        (rule_version, snapshot_id),
    )
    return cur.fetchone()[0] == 0


def list_assessed_grants(conn, snapshot_id: str, rule_version: str):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT gp.principal_id,gp.policy_id,go.grant_id,go.observation_id,
        gra.assessment_id,gra.risk_level
        FROM grant_observations go
        JOIN grant_paths gp ON gp.grant_id=go.grant_id
        JOIN grant_risk_assessments gra ON gra.observation_id=go.observation_id
            AND gra.rule_version=?
        JOIN policy_risk_assessments pra ON pra.assessment_id=gra.policy_assessment_id
            AND pra.snapshot_id=go.snapshot_id AND pra.policy_sha256=go.policy_sha256
        WHERE go.snapshot_id=? ORDER BY go.grant_id""",
        (rule_version, snapshot_id),
    )
    return cur.fetchall()


def create_pinned_campaign(conn, campaign_id: str, name: str, created_at: str, snapshot_id: str):
    db.execute(
        conn.cursor(),
        "INSERT INTO campaigns(campaign_id,name,created_at,snapshot_id) VALUES (?,?,?,?)",
        (campaign_id, name, created_at, snapshot_id),
    )


def create_pinned_review(
    conn, review_id: str, campaign_id: str, user_id: str, role_id: str,
    snapshot_id: str, grant_id: str, observation_id: str,
    risk_assessment_id: str, created_at: str,
) -> bool:
    cur = conn.cursor()
    db.execute(
        cur,
        """INSERT INTO access_reviews
        (review_id,campaign_id,user_id,role_id,status,snapshot_id,grant_id,
         observation_id,risk_assessment_id,created_at)
        VALUES (?,?,?,?,'PENDING',?,?,?,?,?) ON CONFLICT DO NOTHING""",
        (
            review_id, campaign_id, user_id, role_id, snapshot_id, grant_id,
            observation_id, risk_assessment_id, created_at,
        ),
    )
    return cur.rowcount == 1


def review_evidence_binding(conn, review_id: str):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT r.snapshot_id,r.grant_id,r.observation_id,r.risk_assessment_id,
        gp.account_id,ps.source_scope,gp.grant_type,gp.policy_id,
        gp.principal_id,gp.principal_arn
        FROM access_reviews r
        JOIN grant_paths gp ON gp.grant_id=r.grant_id
        JOIN published_snapshots ps ON ps.snapshot_id=r.snapshot_id
        JOIN grant_observations go ON go.observation_id=r.observation_id
            AND go.grant_id=r.grant_id AND go.snapshot_id=r.snapshot_id
        JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id
            AND gra.observation_id=r.observation_id
        JOIN policy_risk_assessments pra ON pra.assessment_id=gra.policy_assessment_id
            AND pra.snapshot_id=r.snapshot_id
            AND pra.policy_id=gp.policy_id
            AND pra.policy_sha256=go.policy_sha256
        JOIN campaigns c ON c.campaign_id=r.campaign_id
            AND c.snapshot_id=r.snapshot_id
        WHERE r.review_id=?""",
        (review_id,),
    )
    row = cur.fetchone()
    if not row or not all(row[:7]):
        return None
    return {
        "snapshot_id": row[0], "grant_id": row[1], "observation_id": row[2],
        "risk_assessment_id": row[3], "account_id": row[4],
        "source_scope": row[5], "grant_type": row[6], "policy_id": row[7],
        "principal_id": row[8], "principal_arn": row[9],
    }


def is_current_grant_for_review(conn, review_id: str) -> bool:
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT 1 FROM access_reviews r
        JOIN grant_observations go
          ON go.observation_id=r.observation_id AND go.grant_id=r.grant_id
             AND go.snapshot_id=r.snapshot_id
        JOIN grant_paths gp ON gp.grant_id=r.grant_id
        JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id
            AND gra.observation_id=r.observation_id
        JOIN published_snapshots ps ON ps.snapshot_id=r.snapshot_id
        JOIN source_publications sp
          ON sp.account_id=gp.account_id AND sp.source_scope=ps.source_scope
             AND sp.snapshot_id=r.snapshot_id
        WHERE r.review_id=? AND r.status='REVOKED' AND r.remediated_at IS NULL""",
        (review_id,),
    )
    return cur.fetchone() is not None


def record_review_decision_event(
    conn, event_id: str, review_id: str, decision: str,
    reviewer_sub: str | None, comment: str, decided_at: str,
):
    cur = conn.cursor()
    db.execute(
        cur,
        """INSERT INTO review_decision_events
        (event_id,review_id,snapshot_id,grant_id,observation_id,risk_assessment_id,
         decision,reviewer_sub,reviewer_comment,decided_at)
        SELECT ?,review_id,snapshot_id,grant_id,observation_id,risk_assessment_id,
               ?,?,?,? FROM access_reviews WHERE review_id=?""",
        (event_id, decision, reviewer_sub, comment, decided_at, review_id),
    )
    if cur.rowcount != 1:
        raise RuntimeError("Review decision event could not be recorded")


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
          AND r.snapshot_id=? AND r.grant_id IS NOT NULL
          AND r.observation_id IS NOT NULL AND r.risk_assessment_id IS NOT NULL
          AND a.approver_sub <> r.reviewer_sub AND a.discovery_run_id=?""",
        (review_id, discovery_run_id, discovery_run_id),
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


def campaign_exists(conn, campaign_id: str) -> bool:
    cur = conn.cursor()
    db.execute(cur, "SELECT 1 FROM campaigns WHERE campaign_id=?", (campaign_id,))
    return cur.fetchone() is not None


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
        SELECT r.review_id,
        CASE WHEN r.observation_id IS NULL THEN u.user_name ELSE go.principal_name END,
        CASE WHEN r.observation_id IS NULL THEN rol.role_name ELSE go.policy_name END,
        CASE WHEN r.observation_id IS NULL THEN rol.role_id ELSE gp.policy_id END
        FROM access_reviews r
        JOIN users u ON r.user_id = u.user_id
        JOIN roles rol ON r.role_id = rol.role_id
        LEFT JOIN grant_observations go ON go.observation_id=r.observation_id
        LEFT JOIN grant_paths gp ON gp.grant_id=r.grant_id
        LEFT JOIN user_roles ur ON ur.user_id = r.user_id AND ur.role_id = r.role_id
        WHERE r.status = 'REVOKED' 
        AND r.remediated_at IS NULL
        AND (r.grant_id IS NOT NULL OR ur.user_id IS NOT NULL)
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
        SELECT r.review_id, r.user_id, r.role_id,
        CASE WHEN r.grant_id IS NULL THEN u.user_name ELSE go.principal_name END,
        CASE WHEN r.grant_id IS NULL THEN rol.role_name ELSE go.policy_name END,
        CASE WHEN r.grant_id IS NULL THEN rol.risk_level ELSE gra.risk_level END
        FROM access_reviews r
        JOIN users u ON r.user_id = u.user_id
        JOIN roles rol ON r.role_id = rol.role_id
        LEFT JOIN grant_observations go ON go.observation_id=r.observation_id
        LEFT JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id
        WHERE (CASE WHEN r.grant_id IS NULL THEN rol.risk_level
                    ELSE gra.risk_level END) = 'HIGH' AND r.status = 'PENDING'
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
        SELECT r.review_id, r.user_id, r.role_id,
        CASE WHEN r.observation_id IS NULL THEN u.user_name ELSE go.principal_name END,
        CASE WHEN r.observation_id IS NULL THEN rol.role_name ELSE go.policy_name END,
        CASE WHEN r.observation_id IS NULL THEN rol.risk_level ELSE gra.risk_level END
        FROM access_reviews r
        JOIN users u ON r.user_id = u.user_id
        JOIN roles rol ON r.role_id = rol.role_id
        LEFT JOIN grant_observations go ON go.observation_id=r.observation_id
        LEFT JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id
        WHERE r.review_id = ?
        """,
        (review_id,),
    )
    return cur.fetchone()


def fetch_review_ai_context(conn, review_id: str):
    cur = conn.cursor()
    db.execute(
        cur,
        """SELECT r.review_id,r.status,r.user_id,r.role_id,
        CASE WHEN r.observation_id IS NULL THEN u.user_name ELSE go.principal_name END,
        CASE WHEN r.observation_id IS NULL THEN rol.role_name ELSE go.policy_name END,
        CASE WHEN r.observation_id IS NULL THEN rol.risk_level ELSE gra.risk_level END,
        CASE WHEN r.observation_id IS NULL THEN rol.policy_document ELSE go.policy_document END,
        CASE WHEN r.observation_id IS NULL THEN ra.reason ELSE pra.reason END,
        CASE WHEN r.observation_id IS NULL THEN ra.evidence ELSE pra.evidence END,
        CASE WHEN r.observation_id IS NULL THEN ra.rule_version ELSE pra.rule_version END,
        r.snapshot_id,r.grant_id,r.observation_id,r.risk_assessment_id,
        gp.grant_type,go.source_name,go.policy_version,go.policy_sha256,
        CASE WHEN r.observation_id IS NULL THEN 'legacy_unknown_path'
             ELSE 'snapshot_pinned' END
        FROM access_reviews r JOIN users u ON u.user_id=r.user_id JOIN roles rol ON rol.role_id=r.role_id
        LEFT JOIN risk_assessments ra ON ra.role_id=rol.role_id
        LEFT JOIN grant_observations go ON go.observation_id=r.observation_id
        LEFT JOIN grant_paths gp ON gp.grant_id=r.grant_id
        LEFT JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id
        LEFT JOIN policy_risk_assessments pra ON pra.assessment_id=gra.policy_assessment_id
        WHERE r.review_id=?""",
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
    """Export frozen grant/risk evidence; legacy rows are explicitly labelled."""
    cur = conn.cursor()
    db.execute(
        cur,
        """
        SELECT 
            r.review_id,
            r.campaign_id,
            CASE WHEN r.observation_id IS NULL THEN u.user_name ELSE go.principal_name END,
            CASE WHEN r.observation_id IS NULL THEN rol.role_name ELSE go.policy_name END,
            CASE WHEN r.observation_id IS NULL THEN rol.risk_level ELSE gra.risk_level END,
            r.status,
            r.reviewer_comment,
            r.ai_risk_summary,
            r.created_at,
            r.reviewed_at,
            r.remediated_at,
            (SELECT source FROM ai_generations g WHERE g.review_id=r.review_id ORDER BY created_at DESC LIMIT 1),
            (SELECT model FROM ai_generations g WHERE g.review_id=r.review_id ORDER BY created_at DESC LIMIT 1),
            (SELECT prompt_version FROM ai_generations g WHERE g.review_id=r.review_id ORDER BY created_at DESC LIMIT 1),
            (SELECT created_at FROM ai_generations g WHERE g.review_id=r.review_id ORDER BY created_at DESC LIMIT 1),
            r.snapshot_id,r.grant_id,r.observation_id,r.risk_assessment_id,
            gp.grant_type,go.source_name,go.policy_version,go.policy_sha256,
            CASE WHEN r.observation_id IS NULL THEN ra.reason ELSE pra.reason END,
            CASE WHEN r.observation_id IS NULL THEN ra.evidence ELSE pra.evidence END,
            CASE WHEN r.observation_id IS NULL THEN ra.rule_version ELSE pra.rule_version END,
            CASE WHEN r.observation_id IS NULL THEN rol.policy_document ELSE go.policy_document END,
            CASE WHEN r.observation_id IS NULL THEN 'legacy_unknown_path'
                 ELSE 'snapshot_pinned' END
        FROM access_reviews r
        JOIN users u ON r.user_id = u.user_id
        JOIN roles rol ON r.role_id = rol.role_id
        LEFT JOIN risk_assessments ra ON ra.role_id=rol.role_id
        LEFT JOIN grant_observations go ON go.observation_id=r.observation_id
        LEFT JOIN grant_paths gp ON gp.grant_id=r.grant_id
        LEFT JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id
        LEFT JOIN policy_risk_assessments pra ON pra.assessment_id=gra.policy_assessment_id
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
