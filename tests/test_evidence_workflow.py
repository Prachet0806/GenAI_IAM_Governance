"""Source-scoped publication and snapshot-pinned certification invariants."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone

import pytest

from common import evidence, repo
from common.db import db
from lambdas.generate_reviews.handler import generate_campaign
from lambdas.risk_evaluation.handler import evaluate_risk
from scripts import migrate


ACCOUNT_A = "123456789012"
ACCOUNT_B = "210987654321"
POLICY_ARN = f"arn:aws:iam::{ACCOUNT_A}:policy/Reader"
READ_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}],
}
WRITE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}],
}


@pytest.fixture
def sqlite_evidence_db(tmp_path, monkeypatch):
    path = tmp_path / "evidence.db"
    monkeypatch.setenv("DB_URL", f"sqlite:///{path}")
    monkeypatch.setenv("LOCAL_ONLY", "true")
    migrate.apply_sqlite()
    return path


def _user(account=ACCOUNT_A):
    return {
        "UserId": f"U-{account}",
        "UserName": f"alice-{account}",
        "Arn": f"arn:aws:iam::{account}:user/alice",
        "CreateDate": datetime.now(timezone.utc),
    }


def _policies(document=READ_POLICY):
    base = {"PolicyArn": POLICY_ARN, "PolicyName": "Reader", "Document": document}
    return [
        {**base, "GrantType": "DIRECT_MANAGED", "SourceId": f"U-{ACCOUNT_A}",
         "SourceName": "alice", "AttachmentId": POLICY_ARN, "PolicyVersion": "v1"},
        {**base, "GrantType": "GROUP_MANAGED", "SourceId": "G-A",
         "SourceName": "group-a", "AttachmentId": POLICY_ARN, "PolicyVersion": "v1"},
        {**base, "GrantType": "GROUP_MANAGED", "SourceId": "G-B",
         "SourceName": "group-b", "AttachmentId": POLICY_ARN, "PolicyVersion": "v1"},
    ]


def _publish(account=ACCOUNT_A, policies=None, mode="AWS"):
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    user = _user(account)
    observations = [
        evidence.grant_observation(account, user, policy, run_id)
        for policy in (policies if policies is not None else _policies())
    ]
    with db.get_connection() as conn:
        repo.lock_inventory_remediation(conn)
        repo.start_discovery_attempt(
            conn, run_id, now, mode, account, evidence.IAM_USER_POLICY_SCOPE
        )
    with db.get_connection() as conn:
        repo.lock_inventory_remediation(conn)
        assert repo.publish_discovery_snapshot(
            conn, run_id, account, evidence.IAM_USER_POLICY_SCOPE,
            now, [user], observations,
            {"complete_for_declared_scope": True, "coverage": ["iam_users"]},
        )
    return run_id, observations


def _attempt(account, status=None):
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with db.get_connection() as conn:
        repo.lock_inventory_remediation(conn)
        repo.start_discovery_attempt(
            conn, run_id, now, "AWS", account, evidence.IAM_USER_POLICY_SCOPE
        )
        if status:
            repo.finish_discovery_run(conn, run_id, now, status, 0, 1, {"test": True})
    return run_id


def test_iam_enumeration_keeps_direct_and_two_group_paths():
    from lambdas.identity_discovery.handler import _user_entitlements

    class FakeIam:
        def list_attached_user_policies(self, **kwargs):
            return {"AttachedPolicies": [{"PolicyArn": POLICY_ARN, "PolicyName": "Reader"}]}

        def list_attached_group_policies(self, **kwargs):
            return {"AttachedPolicies": [{"PolicyArn": POLICY_ARN, "PolicyName": "Reader"}]}

        def get_paginator(self, operation):
            class Paginator:
                def paginate(self, **kwargs):
                    if operation == "list_groups_for_user":
                        return [{"Groups": [
                            {"GroupId": "G-A", "GroupName": "group-a"},
                            {"GroupId": "G-B", "GroupName": "group-b"},
                        ]}]
                    return [{"PolicyNames": []}]

            return Paginator()

        def get_policy(self, **kwargs):
            return {"Policy": {"DefaultVersionId": "v1"}}

        def get_policy_version(self, **kwargs):
            return {"PolicyVersion": {"Document": READ_POLICY}}

    paths = _user_entitlements(FakeIam(), _user())
    assert len(paths) == 3
    assert {path["GrantType"] for path in paths} == {
        "DIRECT_MANAGED", "GROUP_MANAGED"
    }
    assert {path["SourceId"] for path in paths} == {
        f"U-{ACCOUNT_A}", "G-A", "G-B"
    }
    assert {path["PolicyVersion"] for path in paths} == {"v1"}


def test_three_paths_are_distinct_and_old_review_evidence_is_frozen(
    sqlite_evidence_db, tmp_path, monkeypatch
):
    from api import review_service
    from reports.export_audit import export_audit_report

    first_snapshot, first_observations = _publish()
    assert generate_campaign({"account_id": ACCOUNT_A}, None)["reason"] == "snapshot_risk_incomplete"
    assert evaluate_risk(None, None)["grant_observations_assessed"] == 3
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    assert campaign["reviews_created"] == 3
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM user_roles")
        assert cur.fetchone() == (1,)
        cur.execute("SELECT COUNT(*) FROM policy_risk_assessments")
        assert cur.fetchone() == (1,)
        cur.execute("SELECT COUNT(*) FROM grant_risk_assessments")
        assert cur.fetchone() == (3,)
        cur.execute(
            "SELECT review_id,grant_id FROM access_reviews WHERE campaign_id=? ORDER BY grant_id",
            (campaign["campaign_id"],),
        )
        reviews = cur.fetchall()
        assert len({grant_id for _, grant_id in reviews}) == 3
        review_id = reviews[0][0]
        cur.execute(
            "SELECT grant_id,observation_id,risk_assessment_id "
            "FROM access_reviews WHERE campaign_id=? ORDER BY grant_id",
            (campaign["campaign_id"],),
        )
        bindings = cur.fetchall()
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            cur.execute(
                "UPDATE access_reviews SET observation_id=? WHERE review_id=?",
                (bindings[1][1], review_id),
            )
        repo.create_pinned_campaign(
            conn, "invalid-campaign", "invalid",
            datetime.now(timezone.utc).isoformat(), first_snapshot,
        )
        with pytest.raises(sqlite3.IntegrityError, match="does not match"):
            cur.execute(
                """INSERT INTO access_reviews
                (review_id,campaign_id,user_id,role_id,status,snapshot_id,
                 grant_id,observation_id,risk_assessment_id)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    "invalid-review", "invalid-campaign", f"U-{ACCOUNT_A}", POLICY_ARN,
                    "APPROVED", first_snapshot, bindings[0][0],
                    bindings[1][1], bindings[1][2],
                ),
            )
        before = repo.fetch_review_ai_context(conn, review_id)
        repo.assign_campaign_reviewer(conn, campaign["campaign_id"], "reviewer", "admin")
        cur.execute(
            "UPDATE roles SET policy_document=?,risk_level='HIGH',role_name='Changed' WHERE role_id=?",
            (json.dumps(WRITE_POLICY), POLICY_ARN),
        )
    after_mutation = None
    with db.get_connection() as conn:
        after_mutation = repo.fetch_review_ai_context(conn, review_id)
    assert before[4:11] == after_mutation[4:11]
    assert before[19] == "snapshot_pinned"

    monkeypatch.setattr(review_service, "require_reviewer_group", lambda claims: None)
    detail = review_service.get_review(review_id, {"sub": "reviewer"})
    assert detail["snapshot_id"] == first_snapshot
    assert detail["policy_document"] == READ_POLICY
    assert detail["review_scope"] == "GRANT_PATH"
    assert detail["principal_access_status"] == "not_evaluated"

    changed_policies = _policies(WRITE_POLICY)
    for policy in changed_policies:
        policy["PolicyVersion"] = "v2"
    second_snapshot, second_observations = _publish(policies=changed_policies)
    assert second_snapshot != first_snapshot
    assert [item["grant_id"] for item in first_observations] == [
        item["grant_id"] for item in second_observations
    ]
    assert first_observations[0]["policy_sha256"] != second_observations[0]["policy_sha256"]
    with db.get_connection() as conn:
        assert repo.fetch_review_ai_context(conn, review_id)[7] == evidence.canonical_json(READ_POLICY)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE grant_observations SET policy_document='{}' WHERE observation_id=?",
                (first_observations[0]["observation_id"],),
            )
    monkeypatch.chdir(tmp_path)
    result = export_audit_report()
    records = json.loads((tmp_path / result["json"]).read_text(encoding="utf-8"))
    record = next(row for row in records if row["review_id"] == review_id)
    assert record["snapshot_id"] == first_snapshot
    assert record["policy_document"] == READ_POLICY
    assert record["evidence_state"] == "snapshot_pinned"


def test_failed_and_superseded_attempts_preserve_publication_but_block_eligibility(
    sqlite_evidence_db
):
    scope = evidence.IAM_USER_POLICY_SCOPE
    first, _ = _publish()
    failed = _attempt(ACCOUNT_A, "FAILED")
    with db.get_connection() as conn:
        assert repo.published_snapshot(conn, ACCOUNT_A, scope)[0] == first
        assert repo.source_attempt_head(conn, ACCOUNT_A, scope) == failed
        assert repo.eligible_published_snapshot(conn, ACCOUNT_A, scope) is None
    second_account, _ = _publish(
        account=ACCOUNT_B,
        policies=[{
            "PolicyArn": f"arn:aws:iam::{ACCOUNT_B}:policy/Reader",
            "PolicyName": "Reader", "Document": READ_POLICY,
            "GrantType": "DIRECT_MANAGED", "SourceId": f"U-{ACCOUNT_B}",
            "AttachmentId": f"arn:aws:iam::{ACCOUNT_B}:policy/Reader",
        }],
    )
    with db.get_connection() as conn:
        assert repo.eligible_published_snapshot(conn, ACCOUNT_B, scope)["snapshot_id"] == second_account
        assert repo.eligible_published_snapshot(conn, ACCOUNT_A, scope) is None
    older = _attempt(ACCOUNT_A)
    newer = _attempt(ACCOUNT_A)
    with db.get_connection() as conn:
        repo.lock_inventory_remediation(conn)
        assert not repo.publish_discovery_snapshot(
            conn, older, ACCOUNT_A, scope, datetime.now(timezone.utc).isoformat(),
            [], [], {"complete_for_declared_scope": True},
        )
        assert repo.published_snapshot(conn, ACCOUNT_A, scope)[0] == first
        assert repo.source_attempt_head(conn, ACCOUNT_A, scope) == newer
    _publish()
    with db.get_connection() as conn:
        assert repo.eligible_published_snapshot(conn, ACCOUNT_A, scope) is not None


def test_direct_path_remediation_does_not_claim_group_access_removed(
    sqlite_evidence_db, monkeypatch
):
    from lambdas.remediation import handler as remediation

    snapshot_id, _ = _publish(policies=_policies()[:2])
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """SELECT r.review_id FROM access_reviews r
            JOIN grant_paths gp ON gp.grant_id=r.grant_id
            WHERE gp.grant_type='DIRECT_MANAGED'"""
        )
        direct_review = cur.fetchone()[0]
        cur.execute(
            """UPDATE access_reviews SET status='REVOKED',
            reviewer_comment='remove direct grant',reviewer_sub='reviewer'
            WHERE review_id=?""",
            (direct_review,),
        )
        repo.record_remediation_approval(
            conn, str(uuid.uuid4()), direct_review, "approver",
            datetime.now(timezone.utc).isoformat(), snapshot_id,
        )
        assert repo.is_remediation_approved(conn, direct_review, snapshot_id)

    class FakeIam:
        def __init__(self):
            self.attached = True
            self.detaches = 0

        def get_user(self, **kwargs):
            return {"User": {"UserId": f"U-{ACCOUNT_A}", "Arn": _user()["Arn"]}}

        def get_paginator(self, operation):
            assert operation == "list_attached_user_policies"
            return self

        def paginate(self, **kwargs):
            return [{"AttachedPolicies": [{"PolicyArn": POLICY_ARN}] if self.attached else []}]

        def detach_user_policy(self, **kwargs):
            self.detaches += 1
            self.attached = False

    fake = FakeIam()
    monkeypatch.setattr(remediation, "_get_iam_client", lambda: fake)
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("ENABLE_REMEDIATION", "true")
    monkeypatch.setenv("ALLOW_LIVE_REMEDIATION", "true")
    monkeypatch.setenv("REMEDIATION_ALLOWLIST", "Reader")
    monkeypatch.setenv("APP_ENV", "development")
    outcome = remediation.remediate_access(None, None)
    assert outcome["remediated"] == 1
    assert fake.detaches == 1
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT remediated_at FROM access_reviews WHERE review_id=?", (direct_review,))
        assert cur.fetchone()[0]
        cur.execute(
            """SELECT COUNT(*) FROM access_reviews r JOIN grant_paths gp ON gp.grant_id=r.grant_id
            WHERE gp.grant_type='GROUP_MANAGED' AND r.status='PENDING'"""
        )
        assert cur.fetchone() == (1,)


def test_legacy_review_remains_labelled_and_cannot_remediate(sqlite_evidence_db):
    with db.get_connection() as conn:
        repo.insert_user(conn, "legacy-user", "legacy", f"arn:aws:iam::{ACCOUNT_A}:user/legacy",
                         datetime.now(timezone.utc).isoformat())
        repo.insert_role(conn, POLICY_ARN, "Reader")
        repo.link_user_role(conn, "legacy-user", POLICY_ARN)
        repo.create_campaign(conn, "legacy-campaign", "legacy", datetime.now(timezone.utc).isoformat())
        repo.create_review(conn, "legacy-review", "legacy-campaign", "legacy-user", POLICY_ARN,
                           datetime.now(timezone.utc).isoformat())
        row = repo.fetch_review_ai_context(conn, "legacy-review")
        assert row[19] == "legacy_unknown_path"
        assert repo.review_evidence_binding(conn, "legacy-review") is None
        assert not repo.is_remediation_approved(conn, "legacy-review", "anything")


def test_approval_and_live_gate_are_source_specific(sqlite_evidence_db, monkeypatch):
    from fastapi import HTTPException, Response

    from api import review_service
    from lambdas.remediation import handler as remediation

    snapshot_id, _ = _publish(policies=_policies()[:1])
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT review_id FROM access_reviews WHERE campaign_id=?",
                    (campaign["campaign_id"],))
        review_id = cur.fetchone()[0]
        repo.assign_campaign_reviewer(conn, campaign["campaign_id"], "reviewer", "admin")
    monkeypatch.setenv("REVIEWER_GROUP", "reviewers")
    monkeypatch.setenv("REMEDIATION_APPROVER_GROUP", "approvers")
    review_service.decide_review(
        review_id,
        review_service.DecisionRequest(decision="REVOKED", comment="remove path"),
        {"sub": "reviewer", "groups": ["reviewers"]},
    )
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT snapshot_id,grant_id,observation_id,risk_assessment_id "
            "FROM review_decision_events WHERE review_id=?",
            (review_id,),
        )
        event_row = cur.fetchone()
        assert event_row and all(event_row)
    response = Response()
    approval = review_service.approve_remediation(
        review_id, response, {"sub": "approver", "groups": ["approvers"]}
    )
    assert response.status_code == 201
    assert approval["snapshot_id"] == snapshot_id

    _attempt(ACCOUNT_B, "FAILED")
    with db.get_connection() as conn:
        assert repo.eligible_published_snapshot(
            conn, ACCOUNT_A, evidence.IAM_USER_POLICY_SCOPE
        )["snapshot_id"] == snapshot_id
    _attempt(ACCOUNT_A, "FAILED")
    with pytest.raises(HTTPException) as exc:
        review_service.approve_remediation(
            review_id, Response(), {"sub": "approver", "groups": ["approvers"]}
        )
    assert exc.value.status_code == 409
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("ENABLE_REMEDIATION", "true")
    monkeypatch.setenv("ALLOW_LIVE_REMEDIATION", "true")
    monkeypatch.setenv("REMEDIATION_ALLOWLIST", "Reader")
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setattr(
        remediation, "_get_iam_client",
        lambda: pytest.fail("AWS must not be called after a failed source scan"),
    )
    result = remediation.remediate_access(None, None)
    assert result["remediated"] == 0
    assert result["skipped"] == 1
