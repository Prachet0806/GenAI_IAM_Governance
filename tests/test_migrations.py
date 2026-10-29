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
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 3
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
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 3


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
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone() == (3,)
        assert conn.execute("SELECT role_name FROM roles WHERE role_id='R1'").fetchone() == ("Reader",)


def test_sqlite_migration_failure_rolls_back_and_detects_drift(tmp_path, monkeypatch):
    files = tmp_path / "migrations"
    shutil.copytree(migrate.MIGRATIONS_DIR, files)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", files)
    path = tmp_path / "rollback.db"
    _set_sqlite(monkeypatch, path)
    (files / "0004_bad.sql").write_text(
        "CREATE TABLE should_rollback (id INTEGER); INSERT INTO absent VALUES (1);",
        encoding="utf-8",
    )
    with pytest.raises(sqlite3.OperationalError):
        migrate.apply_sqlite()
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []
    (files / "0004_bad.sql").unlink()
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
        assert cur.fetchone() == (3,)
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
