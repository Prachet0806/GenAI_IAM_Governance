"""Regression tests for full-plan deficiency fixes. Run: pytest -q"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_config_redacts_password():
    from common import config

    redacted = config.redact_db_url(
        "postgres://u:secret123@host:5432/db?sslmode=require"
    )
    assert "secret123" not in redacted
    assert "***" in redacted
    assert "host" in redacted


def test_config_sanitize_details():
    from common import config

    out = config.sanitize_details({"db_url": "postgres://u:pw@h/db", "note": "ok"})
    assert out["db_url"] != "postgres://u:pw@h/db"
    assert "pw" not in out["db_url"]
    assert out["note"] == "ok"


def test_sqlite_path_absolute_preserved(tmp_path, monkeypatch):
    from common import config

    monkeypatch.setenv("DB_URL", "sqlite:////tmp/abs_test.db")
    assert config.get_sqlite_path() == os.path.abspath("/tmp/abs_test.db")
    monkeypatch.setenv("DB_URL", "sqlite:///relative_test.db")
    assert config.get_sqlite_path().endswith("relative_test.db")
    assert os.path.isabs(config.get_sqlite_path())
    monkeypatch.setenv("DB_URL", "sqlite:///:memory:")
    assert config.get_sqlite_path() == ":memory:"
    monkeypatch.setenv("DB_URL", "postgres://u:p@h/db")
    assert config.db_is_sqlite() is False


def test_prepare_sql_preserves_json_operator(monkeypatch):
    from common.db import db

    monkeypatch.setenv("DB_URL", "postgres://u:p@h/db")
    db.is_sqlite = False
    sql = "SELECT * FROM t WHERE details ? 'k' AND a = ?"
    out = db.prepare_sql(sql)
    assert "? 'k'" in out  # JSON operator untouched
    assert out.count("%s") == 1


def test_risk_classifier():
    from lambdas.risk_evaluation.handler import classify_risk

    assert classify_risk("AdministratorAccess") == "HIGH"
    assert classify_risk("SuperUserFull") == "HIGH"
    assert classify_risk("PowerUserAccess") == "MEDIUM"
    assert classify_risk("ReadOnlyAccess") == "LOW"
    # 'rewrite' must not trigger write->MEDIUM
    assert classify_risk("rewrite-engine") == "LOW"


def test_remediation_gating_exact_match():
    from lambdas.remediation.handler import _should_detach

    # Exact deny
    allowed, _ = _should_detach(
        "AdministratorAccess", "", allowlist=set(), denylist={"administratoraccess"}
    )
    assert allowed is False
    # Substring should NOT block without wildcards
    allowed, _ = _should_detach(
        "MyAdminAccess", "", allowlist=set(), denylist={"administratoraccess"}
    )
    assert allowed is True
    # Wildcard opts into substring
    allowed, _ = _should_detach(
        "x-break-glass-y", "", allowlist=set(), denylist={"*break-glass*"}
    )
    assert allowed is False
    # Allowlist exact
    allowed, _ = _should_detach(
        "ReadOnlyAccess", "", allowlist={"readonlyaccess"}, denylist=set()
    )
    assert allowed is True
    allowed, _ = _should_detach(
        "OtherAccess", "", allowlist={"readonlyaccess"}, denylist=set()
    )
    assert allowed is False


def test_no_duplicate_repo_function():
    import inspect

    from common import repo

    names = [
        n
        for n, _ in inspect.getmembers(repo, inspect.isfunction)
        if n == "list_high_risk_reviews_missing_ai"
    ]
    assert len(names) == 1


def test_export_query_order_matches_header():
    import inspect

    from common import repo

    src = inspect.getsource(repo.fetch_reviews_for_export)
    # ai_risk_summary must come before created_at to match CSV header order
    assert src.index("ai_risk_summary") < src.index("r.created_at")


def test_migrate_splitter_handles_semicolon_in_string():
    from scripts.migrate import _split_statements

    parts = _split_statements("INSERT INTO t VALUES ('a;b'); SELECT 1;")
    assert len(parts) == 2
    assert "a;b" in parts[0]


def test_ai_handler_disabled_without_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    # Ensure lazy path returns DISABLED rather than raising ImportError
    from lambdas.ai_explanation import handler as ai

    assert ai._get_client() is None
    assert ai.handler(None, None)["status"] == "DISABLED"


def test_group_attached_policy_uses_group_iam_operation():
    from lambdas.identity_discovery.handler import _list_all_attached_policies

    class FakeIam:
        def __init__(self):
            self.calls = []

        def list_attached_user_policies(self, **kwargs):
            self.calls.append(("user", kwargs))
            return {"AttachedPolicies": [{"PolicyArn": "arn:user-policy"}]}

        def list_attached_group_policies(self, **kwargs):
            self.calls.append(("group", kwargs))
            return {"AttachedPolicies": [{"PolicyArn": "arn:group-policy"}]}

    iam = FakeIam()
    user = _list_all_attached_policies(iam, "alice", "user")
    group = _list_all_attached_policies(iam, "engineering", "group")
    assert user[0]["PolicyArn"] == "arn:user-policy"
    assert group[0]["PolicyArn"] == "arn:group-policy"
    assert iam.calls == [
        ("user", {"UserName": "alice"}),
        ("group", {"GroupName": "engineering"}),
    ]


def test_remediation_approval_renews_and_fencing_rejects_stale_worker(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'remediation.db'}")
    from scripts import migrate

    migrate.apply_sqlite()
    from common import repo
    from common.db import db

    with db.get_connection() as conn:
        repo.insert_user(
            conn,
            "U1",
            "user",
            "arn:aws:iam::123:user/user",
            "2026-01-01T00:00:00+00:00",
        )
        repo.insert_role(conn, "R1", "ReadOnlyAccess")
        repo.link_user_role(conn, "U1", "R1")
        repo.create_campaign(conn, "C1", "test", "2026-01-01T00:00:00+00:00")
        repo.create_review(conn, "REV1", "C1", "U1", "R1", "2026-01-01T00:00:00+00:00")
        cur = conn.cursor()
        db.execute(
            cur,
            "UPDATE access_reviews SET status='REVOKED', reviewer_comment='test', reviewer_sub='reviewer' WHERE review_id='REV1'",
        )

        assert repo.record_remediation_approval(
            conn, "A1", "REV1", "approver", "2026-01-01T00:00:00+00:00", "RUN1"
        )
        # Legacy reviews retain approval history but lack the grant/snapshot
        # binding required for live remediation.
        assert not repo.is_remediation_approved(conn, "REV1", "RUN1")
        assert repo.record_remediation_approval(
            conn, "A2", "REV1", "approver", "2026-01-02T00:00:00+00:00", "RUN2"
        )
        assert not repo.is_remediation_approved(conn, "REV1", "RUN1")
        assert not repo.is_remediation_approved(conn, "REV1", "RUN2")
        assert repo.get_remediation_approval(conn, "REV1")[2] == "RUN2"
        assert not repo.record_remediation_approval(
            conn, "A3", "REV1", "other-approver", "2026-01-02T00:00:00+00:00", "RUN2"
        )

        t0 = "2026-01-01T00:00:00+00:00"
        expiry = "2026-01-01T00:05:00+00:00"
        old_epoch = repo.claim_remediation(conn, "REV1", "worker-1", t0, expiry)
        assert old_epoch == 1
        assert (
            repo.claim_remediation(
                conn,
                "REV1",
                "worker-2",
                "2026-01-01T00:04:59+00:00",
                "2026-01-01T00:09:59+00:00",
            )
            is None
        )
        new_epoch = repo.claim_remediation(
            conn, "REV1", "worker-2", expiry, "2026-01-01T00:10:00+00:00"
        )
        assert new_epoch == 2
        assert not repo.renew_remediation_claim(
            conn,
            "REV1",
            "worker-1",
            old_epoch,
            "2026-01-01T00:05:01+00:00",
            "2026-01-01T00:10:01+00:00",
        )
        repo.release_remediation_claim(conn, "REV1", "worker-1", old_epoch)
        assert repo.renew_remediation_claim(
            conn,
            "REV1",
            "worker-2",
            new_epoch,
            "2026-01-01T00:05:01+00:00",
            "2026-01-01T00:10:01+00:00",
        )


def test_mock_org_12_users():
    from lambdas.identity_discovery.handler import _mock_identities

    users = _mock_identities()
    assert len(users) == 12
    names = {u["UserName"] for u in users}
    assert "bob@example.com" in names and "mallory@example.com" in names
    # oscar exercises multi-entitlement
    oscar = next(u for u in users if u["UserName"] == "oscar@example.com")
    assert len(oscar["Policies"]) == 2


def test_risk_classifier_12users():
    from lambdas.risk_evaluation.handler import classify_risk, risk_reason

    assert classify_risk("AdministratorAccess") == "HIGH"
    assert classify_risk("SuperUserFull") == "HIGH"
    assert classify_risk("BreakGlass-AdministratorAccess") == "HIGH"
    assert classify_risk("PowerUserAccess") == "MEDIUM"
    assert classify_risk("DeveloperAccess") == "MEDIUM"
    assert classify_risk("NetworkAdmin") == "MEDIUM"
    assert classify_risk("Put-Delete-Modify-Data") == "MEDIUM"
    assert classify_risk("ReadOnlyAccess") == "LOW"
    assert classify_risk("BillingReadOnly") == "LOW"
    assert classify_risk("SecurityAuditView") == "LOW"
    assert classify_risk("rewrite-engine") == "LOW"
    assert isinstance(risk_reason("AdministratorAccess"), str) and risk_reason(
        "AdministratorAccess"
    )
    assert isinstance(risk_reason("rewrite-engine"), str) and risk_reason(
        "rewrite-engine"
    )
