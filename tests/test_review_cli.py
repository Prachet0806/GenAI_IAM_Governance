"""Tests for scripts/review.py reviewer CLI."""

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _seed_db(tmp_path, monkeypatch, *, source="MOCK"):
    db_file = tmp_path / "review_test.db"
    monkeypatch.setenv("DB_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("MOCK_IAM", "true")
    from scripts import migrate

    migrate.apply_sqlite()
    from common import evidence, repo
    from common.db import db
    from lambdas.risk_evaluation.handler import evaluate_risk

    account = "123456789012"
    scope = evidence.IAM_USER_POLICY_SCOPE
    user = {
        "UserId": "U1", "UserName": "bob@example.com",
        "Arn": f"arn:aws:iam::{account}:user/bob",
        "CreateDate": datetime.now(timezone.utc),
    }
    policies = [
        {"PolicyArn": role_id, "PolicyName": name,
         "Document": {"Statement": [{"Effect": "Allow", "Action": action,
                                      "Resource": resource}]},
         "GrantType": "DIRECT_MANAGED", "SourceId": "U1",
         "SourceName": user["UserName"], "AttachmentId": role_id}
        for role_id, name, action, resource in (
            ("R-HIGH", "AdministratorAccess", "*", "*"),
            ("R-LOW", "ReadOnlyAccess", "s3:GetObject", "arn:aws:s3:::bucket/*"),
        )
    ]
    observations = [
        evidence.grant_observation(account, user, policy, "SNAP1")
        for policy in policies
    ]
    with db.get_connection() as conn:
        now = datetime.now(timezone.utc).isoformat()
        repo.start_discovery_attempt(conn, "SNAP1", now, source, account, scope)
        repo.publish_discovery_snapshot(
            conn, "SNAP1", account, scope, now, [user], observations,
            {"complete_for_declared_scope": True},
        )
    evaluate_risk(None, None)
    with db.get_connection() as conn:
        now = datetime.now(timezone.utc).isoformat()
        repo.create_pinned_campaign(conn, "C1", "test", now, "SNAP1")
        for principal_id, role_id, grant_id, observation_id, assessment_id, _ in repo.list_assessed_grants(
            conn, "SNAP1", evidence.POLICY_RULE_VERSION
        ):
            repo.create_pinned_review(
                conn, f"REV-{'HIGH' if role_id == 'R-HIGH' else 'LOW'}",
                "C1", principal_id, role_id, "SNAP1", grant_id,
                observation_id, assessment_id, now,
            )
    return db_file


def test_decide_revoke_requires_comment(tmp_path, monkeypatch):
    _seed_db(tmp_path, monkeypatch)
    from scripts.review import main

    assert main(["decide", "--review-id", "REV-HIGH", "--decision", "REVOKED"]) == 2


def test_decide_happy_and_double_decide_blocked(tmp_path, monkeypatch, capsys):
    _seed_db(tmp_path, monkeypatch)
    from common.db import db
    from scripts.review import main

    assert (
        main(
            [
                "decide",
                "--review-id",
                "REV-HIGH",
                "--decision",
                "REVOKED",
                "--comment",
                "least privilege",
                "--reviewer",
                "alice",
            ]
        )
        == 0
    )
    # double decide must fail
    assert (
        main(
            [
                "decide",
                "--review-id",
                "REV-HIGH",
                "--decision",
                "APPROVED",
                "--comment",
                "x",
            ]
        )
        == 1
    )
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(
            cur,
            "SELECT status, reviewer_comment FROM access_reviews WHERE review_id='REV-HIGH'",
        )
        status, comment = cur.fetchone()
        assert status == "REVOKED" and "least privilege" in comment


def test_list_filters_and_stats(tmp_path, monkeypatch, capsys):
    _seed_db(tmp_path, monkeypatch)
    from scripts.review import main

    assert main(["list", "--risk", "HIGH"]) == 0
    out = capsys.readouterr().out
    assert "AdministratorAccess" in out and "ReadOnlyAccess" not in out
    assert main(["stats"]) == 0


def test_ai_marker_distinguishes_validated_and_legacy():
    from scripts.review import _ai_marker

    assert _ai_marker(None, None, None) == "-"
    assert _ai_marker("historic", "MODEL", "legacy_compatibility") == "legacy"
    assert "validated" in _ai_marker("current", "MODEL", "validated_artifact")
    assert "fallback" in _ai_marker("fallback", "FALLBACK", "validated_artifact")


def test_auto_demo_revokes_high_approves_low(tmp_path, monkeypatch):
    _seed_db(tmp_path, monkeypatch)
    from common.db import db
    from scripts.review import main

    assert main(["auto-demo"]) == 0
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(
            cur, "SELECT review_id, status FROM access_reviews ORDER BY review_id"
        )
        got = dict(cur.fetchall())
    assert got["REV-HIGH"] == "REVOKED"
    assert got["REV-LOW"] == "APPROVED"


def test_mock_flag_cannot_decide_aws_sourced_review(tmp_path, monkeypatch):
    _seed_db(tmp_path, monkeypatch, source="AWS")
    from common.db import db
    from scripts.review import main

    assert main(["decide", "--review-id", "REV-HIGH", "--decision", "REVOKED",
                 "--comment", "forged", "--reviewer", "forged-sub"]) == 2
    assert main(["auto-demo"]) == 0
    with db.get_connection() as conn:
        assert conn.execute("SELECT status FROM access_reviews WHERE review_id='REV-HIGH'").fetchone() == ("PENDING",)
