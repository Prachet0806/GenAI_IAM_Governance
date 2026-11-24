"""Source-scoped publication and snapshot-pinned certification invariants."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone

import pytest

from common import evidence, evidence_manifest, repo
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


def _publish(account=ACCOUNT_A, policies=None, mode="AWS", user=None):
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    user = user or _user(account)
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
        coverage = {
            "scope_version": evidence.IAM_USER_POLICY_SCOPE,
            "pagination_complete": True,
            "complete_for_declared_scope": True,
            "coverage": ["iam_users"],
        }
        repo.record_collection_success(
            conn, run_id, account, evidence.IAM_USER_POLICY_SCOPE,
            now, [user], observations, coverage,
        )
        assert repo.publish_discovery_snapshot(
            conn, run_id, account, evidence.IAM_USER_POLICY_SCOPE,
            now, [user], observations, coverage,
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


def test_observation_arn_tracks_rename_without_changing_grant_identity(sqlite_evidence_db):
    first_snapshot, first = _publish(policies=_policies()[:1])
    evaluate_risk(None, None)
    first_campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        first_review = conn.execute(
            "SELECT review_id FROM access_reviews WHERE campaign_id=?",
            (first_campaign["campaign_id"],),
        ).fetchone()[0]
        old_binding = repo.review_evidence_binding(conn, first_review)
        conn.execute("UPDATE access_reviews SET status='APPROVED' WHERE review_id=?", (first_review,))
    renamed = {**_user(), "UserName": "alice-renamed",
               "Arn": f"arn:aws:iam::{ACCOUNT_A}:user/alice-renamed"}
    second_snapshot, second = _publish(policies=_policies()[:1], user=renamed)
    assert first_snapshot != second_snapshot
    assert first[0]["grant_id"] == second[0]["grant_id"]
    evaluate_risk(None, None)
    second_campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        second_review = conn.execute(
            "SELECT review_id FROM access_reviews WHERE campaign_id=?",
            (second_campaign["campaign_id"],),
        ).fetchone()[0]
        new_binding = repo.review_evidence_binding(conn, second_review)
        assert repo.review_evidence_binding(conn, first_review)["principal_arn"] == old_binding["principal_arn"]
        assert new_binding["principal_arn"] == renamed["Arn"]
        assert new_binding["principal_name"] == renamed["UserName"]
        assert conn.execute(
            "SELECT principal_arn FROM grant_paths WHERE grant_id=?",
            (first[0]["grant_id"],),
        ).fetchone() == (old_binding["principal_arn"],)


def test_pinned_review_identity_is_checked_and_frozen(sqlite_evidence_db):
    snapshot, _ = _publish(policies=_policies()[:1])
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    now = datetime.now(timezone.utc).isoformat()
    with db.get_connection() as conn:
        review_id, grant_id, observation_id, risk_id = conn.execute(
            "SELECT review_id,grant_id,observation_id,risk_assessment_id "
            "FROM access_reviews WHERE campaign_id=?",
            (campaign["campaign_id"],),
        ).fetchone()
        repo.insert_user(conn, "wrong-user", "wrong", f"arn:aws:iam::{ACCOUNT_A}:user/wrong", now)
        repo.insert_role(conn, "wrong-policy", "wrong")
        repo.create_pinned_campaign(conn, "identity-campaign", "identity", now, snapshot)
        for user_id, role_id in (("wrong-user", POLICY_ARN),
                                 (f"U-{ACCOUNT_A}", "wrong-policy")):
            with pytest.raises(sqlite3.IntegrityError, match="does not match"):
                conn.execute(
                    """INSERT INTO access_reviews
                    (review_id,campaign_id,user_id,role_id,status,snapshot_id,
                     grant_id,observation_id,risk_assessment_id)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), "identity-campaign", user_id, role_id,
                     "PENDING", snapshot, grant_id, observation_id, risk_id),
                )
        for column, value in (("user_id", "wrong-user"), ("role_id", "wrong-policy")):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                conn.execute(
                    f"UPDATE access_reviews SET {column}=? WHERE review_id=?",
                    (value, review_id),
                )


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
        grant_payloads = [
            json.loads(row[0]) for row in conn.execute(
                "SELECT evidence FROM grant_risk_assessments ORDER BY observation_id"
            )
        ]
        assert {item["source_id"] for item in grant_payloads} == {
            f"U-{ACCOUNT_A}", "G-A", "G-B",
        }
        assert len({item["observation_id"] for item in grant_payloads}) == 3
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
        coverage = {
            "scope_version": scope, "pagination_complete": True,
            "complete_for_declared_scope": True,
        }
        repo.record_collection_success(
            conn, older, ACCOUNT_A, scope, datetime.now(timezone.utc).isoformat(),
            [], [], coverage,
        )
        assert not repo.publish_discovery_snapshot(
            conn, older, ACCOUNT_A, scope, datetime.now(timezone.utc).isoformat(),
            [], [], coverage,
        )
        assert repo.discovery_attempt_outcome(conn, older) == {
            "collection": "SUCCEEDED",
            "publication": "SUPERSEDED_BEFORE_PUBLICATION",
        }
        assert repo.published_snapshot(conn, ACCOUNT_A, scope)[0] == first
        assert repo.source_attempt_head(conn, ACCOUNT_A, scope) == newer
    _publish()
    with db.get_connection() as conn:
        assert repo.eligible_published_snapshot(conn, ACCOUNT_A, scope) is not None


def test_collection_receipt_required_and_immutable(sqlite_evidence_db):
    scope = evidence.IAM_USER_POLICY_SCOPE
    run_id = _attempt(ACCOUNT_A)
    now = datetime.now(timezone.utc).isoformat()
    coverage = {
        "scope_version": scope, "pagination_complete": True,
        "complete_for_declared_scope": True, "principal_count": 0,
        "grant_count": 0, "missing_policy_evidence": 0,
    }
    with db.get_connection() as conn:
        with pytest.raises(ValueError, match="receipt"):
            repo.publish_discovery_snapshot(
                conn, run_id, ACCOUNT_A, scope, now, [], [], coverage,
            )
        with pytest.raises(ValueError, match="incomplete"):
            repo.record_collection_success(
                conn, run_id, ACCOUNT_A, scope, now, [], [],
                {**coverage, "pagination_complete": False},
            )
        repo.record_collection_success(
            conn, run_id, ACCOUNT_A, scope, now, [], [], coverage,
        )
    with db.get_connection() as conn:
        assert repo.discovery_attempt_outcome(conn, run_id) == {
            "collection": "SUCCEEDED", "publication": "NOT_PUBLISHED",
        }
        with pytest.raises(ValueError, match="receipt"):
            repo.publish_discovery_snapshot(
                conn, run_id, ACCOUNT_A, scope, now, [], [],
                {**coverage, "grant_count": 1},
            )
        assert repo.publish_discovery_snapshot(
            conn, run_id, ACCOUNT_A, scope, now, [], [], coverage,
        )
        assert repo.publish_discovery_snapshot(
            conn, run_id, ACCOUNT_A, scope, now, [], [], coverage,
        )
        assert conn.execute(
            "SELECT COUNT(*) FROM published_snapshots WHERE snapshot_id=?", (run_id,)
        ).fetchone() == (1,)
        assert repo.discovery_attempt_outcome(conn, run_id) == {
            "collection": "SUCCEEDED", "publication": "CURRENT_PUBLISHED",
        }
        assert conn.execute(
            "SELECT grant_count FROM collection_receipts WHERE run_id=?", (run_id,)
        ).fetchone() == (0,)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute(
                "UPDATE collection_receipts SET grant_count=1 WHERE run_id=?", (run_id,)
            )


def test_legacy_superseded_attempt_has_unknown_collection_outcome(sqlite_evidence_db):
    run_id = _attempt(ACCOUNT_A)
    with db.get_connection() as conn:
        repo.finish_discovery_run(
            conn, run_id, datetime.now(timezone.utc).isoformat(),
            "INCOMPLETE", 0, 0,
            {"snapshot_published": False, "reason": "superseded"},
        )
        assert repo.discovery_attempt_outcome(conn, run_id) == {
            "collection": "UNKNOWN_LEGACY",
            "publication": "SUPERSEDED_BEFORE_PUBLICATION",
        }


def test_single_source_and_review_manifest_remain_pinned(
    sqlite_evidence_db, tmp_path, monkeypatch
):
    from reports.export_audit import export_audit_report
    monkeypatch.setenv("ENABLE_GENAI", "false")
    first, _ = _publish(policies=_policies()[:1])
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        review_id = conn.execute(
            "SELECT review_id FROM access_reviews WHERE campaign_id=?",
            (campaign["campaign_id"],),
        ).fetchone()[0]
        source = evidence_manifest.source_manifest(conn, first)
        pinned = evidence_manifest.review_manifest(conn, review_id)
        assert source["manifest"]["kind"] == "SINGLE_SOURCE"
        assert pinned["manifest"]["source_manifest_sha256"] == source["sha256"]
        assert pinned["manifest"]["attachment_id"] == POLICY_ARN
        assert pinned["sha256"] == evidence_manifest.canonical_hash(pinned["manifest"])
        conn.execute(
            "UPDATE access_reviews SET status='APPROVED' WHERE review_id=?",
            (review_id,),
        )
    _publish(policies=_policies(WRITE_POLICY)[:1])
    with db.get_connection() as conn:
        assert evidence_manifest.source_manifest(conn, first) == source
        assert evidence_manifest.review_manifest(conn, review_id) == pinned
        assert repo.eligible_published_snapshot(conn, ACCOUNT_A) is not None
    monkeypatch.chdir(tmp_path)
    artifact = export_audit_report(account_scopes=[ACCOUNT_A], requested_by="auditor")
    records = json.loads((tmp_path / artifact["json"]).read_text(encoding="utf-8"))
    bundle = json.loads((tmp_path / artifact["evidence"]).read_text(encoding="utf-8"))
    export_manifest = json.loads((tmp_path / artifact["manifest"]).read_text(encoding="utf-8"))
    exported = next(row for row in records if row["review_id"] == review_id)
    assert exported["review_manifest_sha256"] == pinned["sha256"]
    assert exported["source_manifest_sha256"] == source["sha256"]
    assert exported["current_snapshot_eligible_at_export"] is False
    assert bundle["source_manifests"][first] == source
    assert bundle["review_manifests"][review_id] == pinned
    assert export_manifest["artifacts"]["evidence"]["sha256"] == artifact["evidence_sha256"]

    from fastapi.testclient import TestClient
    from api import review_service
    from common import auth

    monkeypatch.setattr(review_service, "__file__", str(tmp_path / "api" / "review_service.py"))
    monkeypatch.setenv("AUDITOR_GROUP", "auditors")
    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "account_scopes")
    monkeypatch.setattr(auth, "verify_access_token", lambda token: {
        "sub": token, "groups": ["auditors"],
        "account_scopes": [ACCOUNT_B] if token == "wrong-account" else [ACCOUNT_A],
    })
    client = TestClient(review_service.app)
    export_id = artifact["export_run_id"]
    headers = {"Authorization": "Bearer auditor"}
    assert client.get(f"/exports/{export_id}/verify", headers=headers).json()["valid"] is True
    downloaded = client.get(
        f"/exports/{export_id}/download?artifact=evidence", headers=headers
    )
    assert downloaded.status_code == 200
    assert json.loads(downloaded.content) == bundle
    assert client.get(f"/exports/{export_id}/verify", headers={
        "Authorization": "Bearer wrong-account"
    }).status_code == 403
    (tmp_path / artifact["evidence"]).write_text("{}", encoding="utf-8")
    verification = client.get(f"/exports/{export_id}/verify", headers=headers).json()
    assert verification["valid"] is False
    assert verification["artifacts"]["evidence"]["valid"] is False


def test_manifest_canonical_hash_uses_unicode_and_explicit_null():
    left = {"name": "café", "ref": None, "items": ["b", "a"]}
    right = {"items": ["b", "a"], "ref": None, "name": "café"}
    assert evidence_manifest.canonical_hash(left) == evidence_manifest.canonical_hash(right)
    assert evidence_manifest.canonical_hash(left) != evidence_manifest.canonical_hash(
        {"name": "café", "items": ["b", "a"]}
    )
    assert evidence_manifest.canonical_hash(left) != evidence_manifest.canonical_hash(
        {"name": "café", "ref": None, "items": ["a", "b"]}
    )


def test_release1_attempt_history_and_bounded_snapshot_comparison(
    sqlite_evidence_db, monkeypatch
):
    from fastapi.testclient import TestClient
    from api.review_service import app
    from common import auth

    first, _ = _publish(policies=_policies()[:2])
    second, _ = _publish(policies=_policies(WRITE_POLICY)[1:])
    failed = _attempt(ACCOUNT_A, "FAILED")
    other, _ = _publish(account=ACCOUNT_B, policies=[])
    monkeypatch.setenv("CAMPAIGN_ADMIN_GROUP", "admins")
    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "account_scopes")
    monkeypatch.setattr(auth, "verify_access_token", lambda token: {
        "sub": token,
        "groups": ["admins"] if token != "reviewer" else ["reviewers"],
        "account_scopes": [ACCOUNT_B] if token == "wrong-account" else [ACCOUNT_A],
    })
    client = TestClient(app)
    headers = {"Authorization": "Bearer admin"}
    attempts = client.get("/discovery-attempts?limit=2", headers=headers)
    assert attempts.status_code == 200
    assert attempts.json()["total"] == 3
    assert attempts.json()["has_more"] is True
    failed_row = next(row for row in client.get(
        "/discovery-attempts?limit=20", headers=headers
    ).json()["attempts"] if row["attempt_id"] == failed)
    assert (failed_row["collection"], failed_row["publication"]) == (
        "FAILED", "NOT_PUBLISHED"
    )
    assert client.get("/discovery-attempts", headers={
        "Authorization": "Bearer reviewer"
    }).status_code == 403
    assert client.get("/discovery-attempts?account_id=" + ACCOUNT_B,
                      headers=headers).status_code == 403
    assert client.get("/discovery-attempts", headers={
        "Authorization": "Bearer wrong-account"
    }).json()["total"] == 1

    result = client.get(
        f"/snapshots/{first}/compare/{second}?limit=1", headers=headers
    )
    assert result.status_code == 200
    data = result.json()
    assert data["counts"] == {"added": 1, "removed": 1, "changed": 1, "unchanged": 0}
    assert data["total"] == 3 and data["has_more"] is True
    assert data["comparison_scope"] == "OBSERVED_GRANT_PATHS_ONLY"
    assert data["before"]["manifest_sha256"] != data["after"]["manifest_sha256"]
    changes = client.get(
        f"/snapshots/{first}/compare/{second}?limit=3", headers=headers
    ).json()["changes"]
    assert {item["kind"] for item in changes} == {"ADDED", "REMOVED", "CHANGED"}
    changed = next(item for item in changes if item["kind"] == "CHANGED")
    assert "policy_sha256" in changed["changed_fields"]
    assert "observed_at" not in changed["changed_fields"]
    assert client.get(f"/snapshots/{first}/compare/{other}", headers=headers).status_code == 404
    assert client.get(f"/snapshots/{first}/compare/{second}", headers={
        "Authorization": "Bearer wrong-account"
    }).status_code == 404


def test_release1_comparison_rejects_cross_scope_and_preserves_empty_scan(
    sqlite_evidence_db
):
    from common import snapshot_history

    first, _ = _publish(policies=[])
    second, _ = _publish(policies=[])
    with db.get_connection() as conn:
        result = snapshot_history.compare_snapshots(conn, first, second, [ACCOUNT_A])
        assert result["counts"] == {
            "added": 0, "removed": 0, "changed": 0, "unchanged": 0,
        }
        assert result["before"]["observation_window"] == {"start": None, "end": None}


def test_release1_auditor_reconstructs_historical_review_with_account_isolation(
    sqlite_evidence_db, monkeypatch
):
    from fastapi.testclient import TestClient
    from api.review_service import app
    from common import auth

    snapshot, observations = _publish(policies=_policies()[:1])
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        review_id = conn.execute(
            "SELECT review_id FROM access_reviews WHERE campaign_id=?",
            (campaign["campaign_id"],),
        ).fetchone()[0]
        frozen = evidence_manifest.review_manifest(conn, review_id)
        source = evidence_manifest.source_manifest(conn, snapshot)
        conn.execute(
            "UPDATE access_reviews SET status='APPROVED',reviewer_sub='reviewer',"
            "reviewer_comment='Business need confirmed',reviewed_at=? WHERE review_id=?",
            (datetime.now(timezone.utc).isoformat(), review_id),
        )
        repo.record_review_decision_event(
            conn, str(uuid.uuid4()), review_id, "APPROVED", "reviewer",
            "Business need confirmed", datetime.now(timezone.utc).isoformat(),
            decision_origin="OIDC_API",
        )
    _publish(policies=_policies(WRITE_POLICY)[:1])
    monkeypatch.setenv("AUDITOR_GROUP", "auditors")
    monkeypatch.setenv("CAMPAIGN_ADMIN_GROUP", "admins")
    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "account_scopes")
    monkeypatch.setattr(auth, "verify_access_token", lambda token: {
        "sub": token,
        "groups": ["reviewers"] if token == "reviewer" else ["auditors"],
        "account_scopes": [ACCOUNT_B] if token == "wrong-account" else [ACCOUNT_A],
    })
    client = TestClient(app)
    endpoint = f"/audit/reviews/{review_id}"
    assert client.get(endpoint, headers={
        "Authorization": "Bearer reviewer"
    }).status_code == 403
    assert client.get(endpoint, headers={
        "Authorization": "Bearer wrong-account"
    }).status_code == 404
    response = client.get(endpoint, headers={"Authorization": "Bearer auditor"})
    assert response.status_code == 200
    body = response.json()
    assert body["review_manifest"] == frozen
    assert body["source_manifest"] == source
    assert body["observed_path"]["attachment_id"] == POLICY_ARN
    assert body["observed_at"] == observations[0]["observed_at"]
    assert body["current_snapshot_eligible"] is False
    assert body["decision_history"][0]["comment"] == "Business need confirmed"
    assert body["status"] == "APPROVED"


def test_invalidation_is_scoped_and_does_not_rewrite_historical_evidence(
    sqlite_evidence_db, tmp_path, monkeypatch
):
    from fastapi.testclient import TestClient
    from api.review_service import app
    from common import auth
    from reports.export_audit import export_audit_report

    snapshot, _ = _publish(policies=_policies()[:1])
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        review_id = conn.execute(
            "SELECT review_id FROM access_reviews WHERE campaign_id=?",
            (campaign["campaign_id"],),
        ).fetchone()[0]
        pinned = evidence_manifest.review_manifest(conn, review_id)
        source = evidence_manifest.source_manifest(conn, snapshot)
    monkeypatch.setenv("CAMPAIGN_ADMIN_GROUP", "admins")
    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "account_scopes")
    monkeypatch.setattr(
        auth, "verify_access_token",
        lambda token: {
            "sub": token,
            "groups": ["admins"] if token != "reviewer" else ["reviewers"],
            "account_scopes": [ACCOUNT_B] if token == "wrong-account" else [ACCOUNT_A],
        },
    )
    client = TestClient(app)
    endpoint = f"/snapshots/{snapshot}/invalidate"
    payload = {"reason_code": "EVIDENCE_DEFECT", "detail": "Policy evidence was incomplete"}
    for token in ("reviewer", "wrong-account"):
        assert client.post(
            endpoint, json=payload, headers={"Authorization": f"Bearer {token}"}
        ).status_code == 403
    response = client.post(
        endpoint, json=payload, headers={"Authorization": "Bearer admin"}
    )
    assert response.status_code == 201
    assert response.json()["manifest_sha256"] == source["sha256"]
    with db.get_connection() as conn:
        assert repo.eligible_published_snapshot(conn, ACCOUNT_A) is None
        assert evidence_manifest.source_manifest(conn, snapshot) == source
        assert evidence_manifest.review_manifest(conn, review_id) == pinned
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute(
                "DELETE FROM evidence_invalidations WHERE snapshot_id=?", (snapshot,)
            )
    review = client.get(
        f"/reviews/{review_id}", headers={"Authorization": "Bearer admin"}
    ).json()
    assert review["review_manifest_sha256"] == pinned["sha256"]
    assert review["snapshot_current_eligible"] is False
    assert review["evidence_invalidations"][0]["reason_code"] == "EVIDENCE_DEFECT"
    monkeypatch.chdir(tmp_path)
    artifact = export_audit_report()
    records = json.loads((tmp_path / artifact["json"]).read_text(encoding="utf-8"))
    exported = next(row for row in records if row["review_id"] == review_id)
    assert exported["review_manifest_sha256"] == pinned["sha256"]
    assert exported["current_snapshot_eligible_at_export"] is False
    assert exported["evidence_invalidations"][0]["reason_code"] == "EVIDENCE_DEFECT"


def test_reviewer_decision_rejects_stale_bound_snapshot(sqlite_evidence_db, monkeypatch):
    from fastapi import HTTPException
    from api import review_service

    _publish()
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT review_id FROM access_reviews WHERE campaign_id=? LIMIT 1",
                    (campaign["campaign_id"],))
        review_id = cur.fetchone()[0]
        repo.assign_campaign_reviewer(conn, campaign["campaign_id"], "reviewer", "admin")
    _attempt(ACCOUNT_A, "FAILED")
    monkeypatch.setenv("REVIEWER_GROUP", "reviewers")

    with pytest.raises(HTTPException) as exc:
        review_service.decide_review(
            review_id,
            review_service.DecisionRequest(decision="APPROVED"),
            {"sub": "reviewer", "groups": ["reviewers"]},
        )
    assert exc.value.status_code == 409
    assert "snapshot" in exc.value.detail.lower()


def test_direct_path_remediation_does_not_claim_group_access_removed(
    sqlite_evidence_db, monkeypatch
):
    from fastapi import Response
    from api import review_service
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
        repo.assign_campaign_reviewer(conn, campaign["campaign_id"], "reviewer", "admin")
    monkeypatch.setenv("REVIEWER_GROUP", "reviewers")
    review_service.decide_review(
        direct_review,
        review_service.DecisionRequest(decision="REVOKED", comment="remove direct grant"),
        {"sub": "reviewer", "groups": ["reviewers"]},
    )
    monkeypatch.setenv("REMEDIATION_APPROVER_GROUP", "approvers")
    review_service.approve_remediation(
        direct_review, Response(), {"sub": "approver", "groups": ["approvers"]},
        review_service.RemediationApprovalRequest(decision="APPROVED", reason="Independent approval"),
    )
    with db.get_connection() as conn:
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

        def get_policy(self, **kwargs):
            return {"Policy": {"DefaultVersionId": "v1"}}

        def get_policy_version(self, **kwargs):
            return {"PolicyVersion": {"Document": READ_POLICY}}

    fake = FakeIam()
    monkeypatch.setattr(remediation, "_get_iam_client", lambda: fake)
    monkeypatch.setenv("MOCK_IAM", "true")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("ENABLE_REMEDIATION", "true")
    monkeypatch.setenv("ALLOW_LIVE_REMEDIATION", "true")
    monkeypatch.setenv("REMEDIATION_ALLOWLIST", "Reader")
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("AWS_ACCOUNT_ID", ACCOUNT_A)
    monkeypatch.setenv("STAGING_REMEDIATION_ACCEPTANCE_ID", "test-acceptance")
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
        review_id, response, {"sub": "approver", "groups": ["approvers"]},
        review_service.RemediationApprovalRequest(decision="APPROVED", reason="Independent approval"),
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
            review_id, Response(), {"sub": "approver", "groups": ["approvers"]},
            review_service.RemediationApprovalRequest(decision="APPROVED", reason="Independent approval"),
        )
    assert exc.value.status_code == 409
    monkeypatch.setenv("MOCK_IAM", "true")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("ENABLE_REMEDIATION", "true")
    monkeypatch.setenv("ALLOW_LIVE_REMEDIATION", "true")
    monkeypatch.setenv("REMEDIATION_ALLOWLIST", "Reader")
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("AWS_ACCOUNT_ID", ACCOUNT_A)
    monkeypatch.setenv("STAGING_REMEDIATION_ACCEPTANCE_ID", "test-acceptance")
    monkeypatch.setattr(
        remediation, "_get_iam_client",
        lambda: pytest.fail("AWS must not be called after a failed source scan"),
    )
    result = remediation.remediate_access(None, None)
    assert result["remediated"] == 0
    assert result["skipped"] == 1


def test_demo_origin_cannot_satisfy_live_approval(sqlite_evidence_db, monkeypatch):
    from fastapi import HTTPException, Response

    from api import review_service

    snapshot_id, _ = _publish(policies=_policies()[:1])
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        review_id = conn.execute(
            "SELECT review_id FROM access_reviews WHERE campaign_id=?",
            (campaign["campaign_id"],),
        ).fetchone()[0]
        conn.execute("""UPDATE access_reviews SET status='REVOKED',
                     reviewer_comment='demo',reviewer_sub='forged-sub'
                     WHERE review_id=?""", (review_id,))
        repo.record_review_decision_event(
            conn, str(uuid.uuid4()), review_id, "REVOKED", "forged-sub",
            "demo", datetime.now(timezone.utc).isoformat(),
            decision_origin="LOCAL_DEMO",
        )
        repo.record_remediation_approval(
            conn, str(uuid.uuid4()), review_id, "approver",
            datetime.now(timezone.utc).isoformat(), snapshot_id,
        )
        assert not repo.is_remediation_approved(conn, review_id, snapshot_id)
    monkeypatch.setenv("REMEDIATION_APPROVER_GROUP", "approvers")
    with pytest.raises(HTTPException) as exc:
        review_service.approve_remediation(
            review_id, Response(), {"sub": "approver", "groups": ["approvers"]},
            review_service.RemediationApprovalRequest(decision="APPROVED", reason="Independent approval"),
        )
    assert exc.value.status_code == 409
