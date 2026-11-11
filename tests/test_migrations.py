"""Migration integrity and database integration checks."""

import os
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from uuid import uuid4

import pytest

from scripts import migrate


def _legacy_baseline_sql():
    """Fixture matching the tables before additive compatibility columns."""
    sql = migrate.load_sql("0001_baseline.sql")
    for line in (
        "    policy_document TEXT,\n",
        "    observed_at TIMESTAMP\n",
        "    reviewer_sub TEXT,\n",
        "    ai_risk_summary TEXT,\n",
        "    discovery_run_id TEXT,\n",
        "    fencing_token INTEGER NOT NULL DEFAULT 0,\n",
    ):
        assert sql.count(line) == 1
        sql = sql.replace(line, "")
    # Remove the commas now trailing the previous columns.
    sql = sql.replace("DEFAULT 'LOW',\n);", "DEFAULT 'LOW'\n);")
    return sql


def _set_sqlite(monkeypatch, path):
    monkeypatch.setenv("DB_URL", f"sqlite:///{path}")


def test_sqlite_fresh_install_and_rerun(tmp_path, monkeypatch):
    path = tmp_path / "fresh.db"
    _set_sqlite(monkeypatch, path)
    migrate.apply_sqlite()
    migrate.apply_sqlite()
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 11
        assert conn.execute("SELECT COUNT(*) FROM governance_mutex").fetchone()[0] == 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_sqlite_legacy_upgrade_preserves_data(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        migrate._execute_statements(conn.cursor(), _legacy_baseline_sql())
        conn.execute("INSERT INTO schema_version(version) VALUES ('legacy')")
        conn.execute("INSERT INTO roles(role_id, role_name) VALUES ('R1', 'Reader')")
    _set_sqlite(monkeypatch, path)
    migrate.apply_sqlite()
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT role_name FROM roles WHERE role_id='R1'").fetchone() == (
            "Reader",
        )
        assert conn.execute(
            "SELECT COUNT(*) FROM schema_version WHERE version='legacy'"
        ).fetchone() == (1,)
        for table, column, _ in migrate.SQLITE_BASELINE_COLUMNS:
            assert column in {
                row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')
            }
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 11


def test_sqlite_upgrade_from_committed_pr1_ledger(tmp_path, monkeypatch):
    source = migrate.MIGRATIONS_DIR
    pr1_files = tmp_path / "pr1-migrations"
    pr1_files.mkdir()
    shutil.copy(source / "0001_baseline.sql", pr1_files)
    path = tmp_path / "pr1.db"
    _set_sqlite(monkeypatch, path)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", pr1_files)
    migrate.apply_sqlite()
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO roles(role_id,role_name) VALUES ('R1','Reader')")
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", source)
    migrate.apply_sqlite()
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone() == (11,)
        assert conn.execute("SELECT role_name FROM roles WHERE role_id='R1'").fetchone() == ("Reader",)


def test_sqlite_upgrade_from_pr3_with_existing_grant_evidence(tmp_path, monkeypatch):
    source = migrate.MIGRATIONS_DIR
    pr3_files = tmp_path / "pr3-migrations"
    pr3_files.mkdir()
    for number in ("0001", "0002", "0003"):
        for path in source.glob(f"{number}_*"):
            shutil.copy(path, pr3_files)
    path = tmp_path / "pr3.db"
    _set_sqlite(monkeypatch, path)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", pr3_files)
    migrate.apply_sqlite()
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("INSERT INTO discovery_runs(run_id,started_at,status,source,account_id,source_scope) VALUES ('SNAP1','2026-01-01','COMPLETE','AWS:scope','123456789012','scope')")
        conn.execute("INSERT INTO published_snapshots(snapshot_id,account_id,source_scope,published_at,users_seen,coverage) VALUES ('SNAP1','123456789012','scope','2026-01-01',1,'{}')")
        conn.execute("INSERT INTO users(user_id,user_name) VALUES ('U1','alice')")
        conn.execute("INSERT INTO roles(role_id,role_name) VALUES ('P1','Reader')")
        conn.execute("INSERT INTO grant_paths(grant_id,account_id,principal_id,principal_arn,grant_type,source_id,attachment_id,policy_id) VALUES ('G1','123456789012','U1','arn:aws:iam::123456789012:user/alice','DIRECT_MANAGED','U1','policy','P1')")
        conn.execute("INSERT INTO grant_observations(observation_id,snapshot_id,grant_id,principal_name,source_name,policy_name,policy_sha256,policy_document,observed_at) VALUES ('O1','SNAP1','G1','alice','alice','Reader','hash','{}','2026-01-01')")
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", source)
    migrate.apply_sqlite()
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("SELECT grant_type FROM grant_paths WHERE grant_id='G1'").fetchone() == ("DIRECT_MANAGED",)
        assert conn.execute("SELECT evidence_status FROM grant_observations WHERE observation_id='O1'").fetchone() == ("COMPLETE",)
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone() == (11,)
        assert conn.execute("SELECT principal_arn FROM grant_observations WHERE observation_id='O1'").fetchone() == (None,)


def test_sqlite_migration_failure_rolls_back_and_detects_drift(tmp_path, monkeypatch):
    files = tmp_path / "migrations"
    shutil.copytree(migrate.MIGRATIONS_DIR, files)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", files)
    path = tmp_path / "rollback.db"
    _set_sqlite(monkeypatch, path)
    (files / "0012_bad.sql").write_text(
        "CREATE TABLE should_rollback (id INTEGER); INSERT INTO absent VALUES (1);",
        encoding="utf-8",
    )
    with pytest.raises(sqlite3.OperationalError):
        migrate.apply_sqlite()
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []
    (files / "0012_bad.sql").unlink()
    migrate.apply_sqlite()
    baseline = files / "0001_baseline.sql"
    baseline.write_text(
        baseline.read_text(encoding="utf-8") + "\n-- changed\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="history differs"):
        migrate.apply_sqlite()


@pytest.fixture
def postgres_schema(monkeypatch):
    url = os.getenv("POSTGRES_TEST_URL")
    if not url:
        pytest.skip("POSTGRES_TEST_URL is required for Postgres integration tests")
    psycopg2 = pytest.importorskip("psycopg2")
    from psycopg2 import sql

    schema = "test_" + uuid4().hex
    admin = psycopg2.connect(url)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("options", f"-c search_path={schema}"))
    dsn = urlunsplit(parsed._replace(query=urlencode(query, quote_via=quote)))
    monkeypatch.setenv("DB_URL", dsn)
    try:
        yield dsn
    finally:
        with admin.cursor() as cur:
            cur.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        admin.close()


def test_postgres_fresh_install_and_concurrent_migration(postgres_schema):
    import psycopg2

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: migrate.apply_postgres(), range(2)))
    assert results == [None, None]
    with psycopg2.connect(postgres_schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT version, length(checksum) FROM schema_migrations")
        assert cur.fetchall() == [
            ("0001_baseline", 64),
            ("0002_grant_evidence", 64),
            ("0003_pinned_reviews", 64),
            ("0004_campaign_workflow", 64),
            ("0005_source_coverage", 64),
            ("0006_ai_artifacts", 64),
            ("0007_decision_origin", 64),
            ("0008_ai_job_recovery", 64),
            ("0009_remediation_evidence", 64),
            ("0010_observation_identity_reconciliation", 64),
            ("0011_remediation_approval_declines", 64),
        ]
        cur.execute("SELECT COUNT(*) FROM governance_mutex")
        assert cur.fetchone() == (1,)


def test_postgres_legacy_upgrade_and_claim_contention(postgres_schema):
    import psycopg2

    with psycopg2.connect(postgres_schema) as conn, conn.cursor() as cur:
        migrate._execute_statements(cur, _legacy_baseline_sql())
        cur.execute("INSERT INTO schema_version(version) VALUES ('legacy')")
        cur.execute("INSERT INTO roles(role_id,role_name) VALUES ('R1','Reader')")
    migrate.apply_postgres()
    with psycopg2.connect(postgres_schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT role_name, policy_document FROM roles WHERE role_id='R1'")
        assert cur.fetchone() == ("Reader", None)
        cur.execute("SELECT COUNT(*) FROM schema_version WHERE version='legacy'")
        assert cur.fetchone() == (1,)
        cur.execute("INSERT INTO users(user_id,user_name) VALUES ('U1','alice')")
        cur.execute("INSERT INTO campaigns(campaign_id,name) VALUES ('C1','test')")
        cur.execute(
            "INSERT INTO access_reviews(review_id,campaign_id,user_id,role_id) "
            "VALUES ('REV1','C1','U1','R1')"
        )

    def claim(worker):
        from common import repo

        with psycopg2.connect(postgres_schema) as conn:
            return repo.claim_remediation(
                conn, "REV1", worker, "2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00"
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, ("worker-1", "worker-2")))
    assert results.count(1) == 1
    assert results.count(None) == 1


def test_postgres_upgrade_from_committed_pr1_ledger(postgres_schema, tmp_path, monkeypatch):
    import psycopg2

    source = migrate.MIGRATIONS_DIR
    pr1_files = tmp_path / "pr1-migrations"
    pr1_files.mkdir()
    shutil.copy(source / "0001_baseline.sql", pr1_files)
    shutil.copy(source / "0001_baseline.postgres.sql", pr1_files)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", pr1_files)
    migrate.apply_postgres()
    with psycopg2.connect(postgres_schema) as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO roles(role_id,role_name) VALUES ('R1','Reader')")
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", source)
    migrate.apply_postgres()
    with psycopg2.connect(postgres_schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM schema_migrations")
        assert cur.fetchone() == (11,)
        cur.execute("SELECT role_name FROM roles WHERE role_id='R1'")
        assert cur.fetchone() == ("Reader",)


def test_postgres_source_publication_and_pinned_reviews(postgres_schema):
    import psycopg2

    from common import evidence, repo
    from common.db import db
    from lambdas.generate_reviews.handler import generate_campaign
    from lambdas.risk_evaluation.handler import evaluate_risk
    from tests.test_evidence_workflow import ACCOUNT_A, _attempt, _publish

    migrate.apply_postgres()
    snapshot_id, observations = _publish()
    assert len({item["grant_id"] for item in observations}) == 3
    assert evaluate_risk(None, None)["grant_observations_assessed"] == 3
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    assert campaign["reviews_created"] == 3
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(DISTINCT grant_id) FROM access_reviews WHERE snapshot_id=%s",
            (snapshot_id,),
        )
        assert cur.fetchone() == (3,)
        cur.execute(
            "SELECT review_id,grant_id,observation_id,risk_assessment_id "
            "FROM access_reviews WHERE campaign_id=%s LIMIT 1",
            (campaign["campaign_id"],),
        )
        review_id, grant_id, observation_id, risk_id = cur.fetchone()
        assert repo.review_evidence_binding(conn, review_id)["principal_arn"] == (
            f"arn:aws:iam::{ACCOUNT_A}:user/alice"
        )
        repo.insert_user(conn, "wrong-user", "wrong", f"arn:aws:iam::{ACCOUNT_A}:user/wrong", "2026-01-01")
        repo.insert_role(conn, "wrong-policy", "Wrong")
        repo.create_pinned_campaign(conn, "identity-campaign", "identity", "2026-01-01", snapshot_id)
    for user_id, role_id in (("wrong-user", observations[0]["policy_id"]),
                             (f"U-{ACCOUNT_A}", "wrong-policy")):
        with pytest.raises(psycopg2.errors.RaiseException, match="does not match"):
            with psycopg2.connect(postgres_schema) as conn, conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO access_reviews
                    (review_id,campaign_id,user_id,role_id,status,snapshot_id,
                     grant_id,observation_id,risk_assessment_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (str(uuid4()), "identity-campaign", user_id, role_id,
                     "PENDING", snapshot_id, grant_id, observation_id, risk_id),
                )
    for column, value in (("user_id", "wrong-user"), ("role_id", "wrong-policy")):
        with pytest.raises(psycopg2.errors.RaiseException, match="immutable"):
            with psycopg2.connect(postgres_schema) as conn, conn.cursor() as cur:
                cur.execute(f"UPDATE access_reviews SET {column}=%s WHERE review_id=%s",
                            (value, review_id))
    _attempt(ACCOUNT_A, "FAILED")
    with db.get_connection() as conn:
        assert repo.published_snapshot(
            conn, ACCOUNT_A, evidence.IAM_USER_POLICY_SCOPE
        )[0] == snapshot_id
        assert repo.eligible_published_snapshot(
            conn, ACCOUNT_A, evidence.IAM_USER_POLICY_SCOPE
        ) is None
    with pytest.raises(psycopg2.errors.RaiseException):
        with psycopg2.connect(postgres_schema) as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE grant_observations SET policy_document='{}' WHERE observation_id=%s",
                (observations[0]["observation_id"],),
            )


def test_postgres_legacy_ai_explanation_projection(postgres_schema):
    """Exercise the compatibility lookup and timestamp ordering on Postgres."""
    import hashlib

    from common import repo
    from common.db import db

    migrate.apply_postgres()
    with db.get_connection() as conn:
        repo.insert_user(conn, "U1", "alice", "arn:aws:iam::123:user/alice", "2026-01-01T00:00:00+00:00")
        repo.insert_role(conn, "R1", "Reader", "LOW")
        repo.create_campaign(conn, "C1", "test", "2026-01-01T00:00:00+00:00")
        repo.create_review(conn, "REV1", "C1", "U1", "R1", "2026-01-01T00:00:00+00:00")
        db.execute(conn.cursor(), "UPDATE access_reviews SET ai_risk_summary=? WHERE review_id=?", ("First", "REV1"))
        for generation_id, summary, when in (
            ("GEN1", "First", "2026-01-02T00:00:00+00:00"),
            ("GEN2", "Second", "2026-01-03T00:00:00+00:00"),
        ):
            repo.record_ai_generation(
                conn, generation_id, "REV1", "MODEL", "SUCCESS", "model", "v1",
                "input-hash", hashlib.sha256(summary.encode("utf-8")).hexdigest(),
                summary, when,
            )
    with db.get_connection() as conn:
        explanation = repo.fetch_legacy_ai_explanation(conn, "REV1")
    assert explanation["summary"] == "First"
    assert explanation["generation_id"] == "GEN1"
    assert explanation["provenance_state"] == "older_matching_generation"


def test_postgres_ai_claim_contention(postgres_schema):
    """A duplicate worker delivery may acquire only one lease."""
    import psycopg2

    from common import ai_artifacts, evidence, repo
    from common.db import db
    from lambdas.generate_reviews.handler import generate_campaign
    from lambdas.risk_evaluation.handler import evaluate_risk
    from tests.test_evidence_workflow import ACCOUNT_A, _user

    migrate.apply_postgres()
    user = _user()
    run_id = "ai-postgres-snapshot"
    policy = {
        "PolicyArn": f"arn:aws:iam::{ACCOUNT_A}:policy/Wildcard",
        "PolicyName": "Wildcard",
        "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        "GrantType": "DIRECT_MANAGED", "SourceId": user["UserId"],
        "SourceName": user["UserName"],
        "AttachmentId": f"arn:aws:iam::{ACCOUNT_A}:policy/Wildcard",
    }
    observation = evidence.grant_observation(ACCOUNT_A, user, policy, run_id)
    now = user["CreateDate"].isoformat()
    with db.get_connection() as conn:
        repo.start_discovery_attempt(conn, run_id, now, "MOCK", ACCOUNT_A, evidence.IAM_USER_POLICY_SCOPE)
        repo.publish_discovery_snapshot(conn, run_id, ACCOUNT_A, evidence.IAM_USER_POLICY_SCOPE,
                                        now, [user], [observation], {"complete_for_declared_scope": True})
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    assert campaign["reviews_created"] == 1
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(cur, "SELECT review_id FROM access_reviews WHERE campaign_id=?", (campaign["campaign_id"],))
        ai_artifacts.enqueue_review(conn, cur.fetchone()[0], pseudonym_key="test-key")

    def claim(_):
        with psycopg2.connect(postgres_schema) as conn:
            return ai_artifacts.claim_job(conn)

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(claim, (1, 2)))
    assert sum(item is not None for item in claims) == 1


def test_postgres_role_identity_center_and_campaign_workflow(postgres_schema):
    """The new grant types and lifecycle SQL run against a real Postgres schema."""
    from datetime import datetime, timezone

    from common import evidence, repo, workflow
    from common.db import db
    from common.source_scanner import publish_source
    from lambdas.generate_reviews.handler import generate_campaign
    from lambdas.risk_evaluation.handler import evaluate_risk

    migrate.apply_postgres()
    account = "123456789012"
    role = {
        "UserId": "ROLE1", "UserName": "role-1",
        "Arn": f"arn:aws:iam::{account}:role/role-1",
        "CreateDate": datetime.now(timezone.utc), "PrincipalKind": "IAM_ROLE",
        "Policies": [{
            "PolicyArn": "trust:role-1", "PolicyName": "role-1:trust",
            "Document": {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                       "Principal": "*"}]},
            "GrantType": "ROLE_TRUST", "SourceId": "ROLE1",
            "SourceName": "role-1", "AttachmentId": "trust",
        }],
    }
    assert publish_source(
        account, evidence.IAM_ROLE_POLICY_SCOPE, [role],
        covered=["role_trust"], unassessed=["effective_permissions"],
    )["status"] == "COMPLETE"
    identity = {
        "UserId": "IC1", "UserName": "ic-user",
        "Arn": "identity-center://instance/user/IC1",
        "CreateDate": datetime.now(timezone.utc),
        "PrincipalKind": "IDENTITY_CENTER_USER",
        "Policies": [{
            "PolicyArn": "permission-set-1", "PolicyName": "PermissionSet1",
            "Document": {}, "EvidenceStatus": "MISSING",
            "MissingReason": "customer_managed_policy_reference_unresolved",
            "GrantType": "IDENTITY_CENTER_ASSIGNMENT",
            "SourceId": "permission-set-1", "SourceName": "PermissionSet1",
            "AttachmentId": f"{account}:USER:IC1",
        }],
    }
    assert publish_source(
        account, evidence.IDENTITY_CENTER_SCOPE, [identity],
        covered=["account_assignments"], unassessed=["group_membership"],
    )["missing_policy_evidence"] == 1
    assert evaluate_risk(None, None)["grant_observations_assessed"] == 2
    campaign = generate_campaign({
        "account_id": account, "source_scope": evidence.IDENTITY_CENTER_SCOPE,
    }, None)
    assert campaign["reviews_created"] == 1
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(cur, "SELECT review_id FROM access_reviews WHERE campaign_id=?", (campaign["campaign_id"],))
        review_id = cur.fetchone()[0]
        repo.assign_campaign_reviewer(conn, campaign["campaign_id"], "reviewer", "admin")
        assert workflow.assign_review(conn, review_id, "reviewer", "admin") == "assigned"
        assert workflow.queue(conn, "reviewer")[0]["review_id"] == review_id
        assert workflow.set_exception(conn, review_id, "OPEN", "reviewer", "Need owner") == "updated"
        assert workflow.change_campaign_state(conn, campaign["campaign_id"], "CLOSED", "admin") == "incomplete"
        assert workflow.set_exception(conn, review_id, "RESOLVED", "admin", "Done") == "updated"
        assert workflow.change_campaign_state(conn, campaign["campaign_id"], "PAUSED", "admin") == "updated"
        paused_queue = workflow.queue(conn, "reviewer")
        assert len(paused_queue) == 1
        assert paused_queue[0]["state"] == "PAUSED"


def test_postgres_remediation_approval_events_and_worker_contention(
    postgres_schema, monkeypatch
):
    """Only one concurrent worker acts; evidence is immutable on Postgres."""
    import psycopg2
    from fastapi import Response

    from api import review_service
    from common import repo
    from common.db import db
    from lambdas.generate_reviews.handler import generate_campaign
    from lambdas.remediation import handler as remediation
    from lambdas.risk_evaluation.handler import evaluate_risk
    from tests.test_evidence_workflow import ACCOUNT_A, _policies, _publish
    from tests.test_remediation_workflow import FakeIam

    migrate.apply_postgres()
    _publish(policies=_policies()[:1])
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT review_id FROM access_reviews WHERE campaign_id=%s",
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
    review_service.approve_remediation(
        review_id, Response(), {"sub": "approver", "groups": ["approvers"]}
    )
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("ENABLE_REMEDIATION", "true")
    monkeypatch.setenv("ALLOW_LIVE_REMEDIATION", "true")
    monkeypatch.setenv("REMEDIATION_ALLOWLIST", "Reader")
    monkeypatch.setenv("AWS_ACCOUNT_ID", ACCOUNT_A)
    monkeypatch.setenv("STAGING_REMEDIATION_ACCEPTANCE_ID", "pg-test-acceptance")
    monkeypatch.setenv("APP_ENV", "staging")
    fake = FakeIam()
    monkeypatch.setattr(remediation, "_get_iam_client", lambda: fake)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda _: remediation.remediate_access(None, None), (1, 2)
        ))
    assert fake.actions == 1
    assert sum(item["remediated"] for item in results) == 1
    with db.get_connection() as conn:
        history = repo.remediation_history(conn, review_id)
        assert [item["event_type"] for item in history["action_events"]] == [
            "PREFLIGHT_PASSED", "ACTION_REQUESTED", "ACTION_VERIFIED"
        ]
        with pytest.raises(psycopg2.errors.RaiseException):
            db.execute(conn.cursor(), "DELETE FROM remediation_approval_events")


def test_postgres_remediation_approval_decline_are_mutually_exclusive(
    postgres_schema, monkeypatch
):
    """Concurrent approvers cannot record both terminal outcomes or execute a decline."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from fastapi import HTTPException, Response

    from api import review_service
    from common import repo
    from common.db import db
    from lambdas.generate_reviews.handler import generate_campaign
    from lambdas.remediation import handler as remediation
    from lambdas.risk_evaluation.handler import evaluate_risk
    from tests.test_evidence_workflow import ACCOUNT_A, _policies, _publish
    from tests.test_remediation_workflow import FakeIam

    migrate.apply_postgres()
    _publish(policies=_policies()[:1])
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT review_id FROM access_reviews WHERE campaign_id=%s",
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

    barrier = Barrier(2)

    def attempt(decision):
        barrier.wait()
        try:
            if decision == "APPROVED":
                return review_service.approve_remediation(
                    review_id, Response(), {"sub": "approver-a", "groups": ["approvers"]},
                    review_service.RemediationApprovalRequest(
                        decision="APPROVED", reason="Approved independently"
                    ),
                )["status"]
            return review_service.decide_remediation_approval(
                review_id,
                review_service.RemediationApprovalRequest(
                    decision="DECLINED", reason="Declined independently"
                ),
                Response(),
                {"sub": "approver-b", "groups": ["approvers"]},
            )["status"]
        except HTTPException as exc:
            assert exc.status_code == 409
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, ("APPROVED", "DECLINED")))
    assert outcomes.count("conflict") == 1
    assert sum(outcome in ("approved", "declined") for outcome in outcomes) == 1

    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM remediation_approval_events WHERE review_id=%s",
            (review_id,),
        )
        approval_count = cur.fetchone()[0]
        cur.execute(
            "SELECT COUNT(*) FROM remediation_approval_declines WHERE review_id=%s",
            (review_id,),
        )
        decline_count = cur.fetchone()[0]
        assert (approval_count, decline_count) in ((1, 0), (0, 1))
        if decline_count:
            binding = repo.review_evidence_binding(conn, review_id)
            assert not repo.is_remediation_approved(
                conn, review_id, binding["snapshot_id"]
            )

    if outcomes[1] == "declined":
        monkeypatch.setenv("MOCK_IAM", "false")
        monkeypatch.setenv("DRY_RUN", "false")
        monkeypatch.setenv("ENABLE_REMEDIATION", "true")
        monkeypatch.setenv("ALLOW_LIVE_REMEDIATION", "true")
        monkeypatch.setenv("REMEDIATION_ALLOWLIST", "Reader")
        monkeypatch.setenv("AWS_ACCOUNT_ID", ACCOUNT_A)
        monkeypatch.setenv("STAGING_REMEDIATION_ACCEPTANCE_ID", "pg-test-acceptance")
        monkeypatch.setenv("APP_ENV", "staging")
        fake = FakeIam()
        monkeypatch.setattr(remediation, "_get_iam_client", lambda: fake)
        assert remediation.remediate_access(None, None)["remediated"] == 0
        assert fake.actions == 0


def test_postgres_operator_reconciliation_is_lease_bound(postgres_schema, monkeypatch):
    """A held action requires an operator request and a verified read-only result."""
    import psycopg2
    from fastapi import Response

    from api import review_service
    from common import repo
    from common.db import db
    from lambdas.generate_reviews.handler import generate_campaign
    from lambdas.remediation import handler as remediation
    from lambdas.risk_evaluation.handler import evaluate_risk
    from tests.test_evidence_workflow import ACCOUNT_A, _policies, _publish
    from tests.test_remediation_workflow import FakeIam

    migrate.apply_postgres()
    _publish(policies=_policies()[:1])
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(cur, "SELECT review_id FROM access_reviews WHERE campaign_id=?",
                   (campaign["campaign_id"],))
        review_id = cur.fetchone()[0]
        repo.assign_campaign_reviewer(conn, campaign["campaign_id"], "reviewer", "admin")
    monkeypatch.setenv("REVIEWER_GROUP", "reviewers")
    monkeypatch.setenv("REMEDIATION_APPROVER_GROUP", "approvers")
    monkeypatch.setenv("REMEDIATION_OPERATOR_GROUP", "operators")
    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "aws_account_scopes")
    review_service.decide_review(
        review_id, review_service.DecisionRequest(decision="REVOKED", comment="remove path"),
        {"sub": "reviewer", "groups": ["reviewers"],
         "aws_account_scopes": [ACCOUNT_A]},
    )
    review_service.approve_remediation(
        review_id, Response(), {"sub": "approver", "groups": ["approvers"],
                                "aws_account_scopes": [ACCOUNT_A]},
    )
    for key, value in {
        "MOCK_IAM": "false", "DRY_RUN": "false", "ENABLE_REMEDIATION": "true",
        "ALLOW_LIVE_REMEDIATION": "true", "REMEDIATION_ALLOWLIST": "Reader",
        "AWS_ACCOUNT_ID": ACCOUNT_A,
        "STAGING_REMEDIATION_ACCEPTANCE_ID": "pg-test-acceptance",
        "APP_ENV": "staging",
    }.items():
        monkeypatch.setenv(key, value)
    fake = FakeIam(remains=True)
    monkeypatch.setattr(remediation, "_get_iam_client", lambda: fake)
    assert remediation.remediate_access(None, None)["reconciliation_required"] == 1
    request = review_service.request_remediation_reconciliation(
        review_id, review_service.ExceptionRequest(reason="Inspect uncertain detach"),
        {"sub": "operator", "groups": ["operators"],
         "aws_account_scopes": [ACCOUNT_A]},
    )
    fake.present = False
    assert remediation.remediate_access(None, None)["remediated"] == 1
    assert fake.actions == 1
    with db.get_connection() as conn:
        history = repo.remediation_history(conn, review_id)
        assert history["reconciliation_events"][0]["request_id"] == request["request_id"]
        assert history["reconciliation_events"][-1]["event_type"] == "VERIFIED_ABSENT"
        assert history["reconciliation_required"] is False
    with pytest.raises(psycopg2.errors.RaiseException):
        with psycopg2.connect(postgres_schema) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM remediation_reconciliation_events")
