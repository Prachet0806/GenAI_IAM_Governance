"""Fixture arithmetic and benchmark safety without a running emulator."""

import json
import pytest

from benchmarks.floci_fixture import make_manifest
from benchmarks.report import summarize
from benchmarks.run_floci_benchmark import _fresh_db
from benchmarks.risk_sql_profile import _normalized, _p95, profile_risk_stage
from common.db import db
from scripts import migrate


@pytest.fixture(autouse=True)
def benchmark_account(monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.setenv("AWS_ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("FLOCI_ACCOUNT_ID", "111111111111")


def test_baseline_manifest_is_deterministic_and_counts_distinct_grants():
    manifest = make_manifest("baseline", 42)
    assert manifest == make_manifest("baseline", 42)
    assert manifest["counts"] == {
        "users": 100, "groups": 4, "roles": 0, "managed_policies": 6,
        "inline_policies": 28, "memberships": 114, "attachments": 109,
        "grant_paths": 357, "observations": 357,
    }
    assert len({tuple(grant) for grant in manifest["expected_grants"]}) == 357
    assert {grant[1] for grant in manifest["expected_grants"]} == {
        "DIRECT_MANAGED", "DIRECT_INLINE", "GROUP_MANAGED", "GROUP_INLINE",
    }
    assert len([user for user in manifest["users"].values()
                if not user["managed"] and not user["inline"] and not user["groups"]]) == 5


def test_seed_changes_distribution_without_changing_counts():
    first = make_manifest("baseline", 42)
    second = make_manifest("baseline", 43)
    assert first["counts"] == second["counts"]
    assert [u["managed"] for u in first["users"].values()] != [
        u["managed"] for u in second["users"].values()
    ]


def test_existing_sqlite_database_is_not_reused(tmp_path):
    path = tmp_path / "existing.db"
    path.write_bytes(b"existing")
    with pytest.raises(RuntimeError, match="already exists"):
        _fresh_db(f"sqlite:///{path}")


def test_risk_sql_profiler_counts_client_calls_without_changing_results(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'profile.db'}")
    with db.get_connection() as conn:
        conn.execute("CREATE TABLE probe (value INTEGER)")

    def stage():
        with db.get_connection() as conn:
            db.execute(conn.cursor(), "INSERT INTO probe(value) VALUES (?)", (1,))
            cur = conn.cursor()
            db.execute(cur, "SELECT value\n FROM probe")
            return cur.fetchall()

    value, profile = profile_risk_stage(stage)
    assert value == [(1,)]
    assert profile["statement_count"] == 2
    assert profile["transaction_count"] == 1
    assert profile["stage_wall_seconds"] >= profile["client_sql_seconds"] >= 0
    assert [row["count"] for row in profile["statements"]] == [1, 1]
    assert _normalized("SELECT   value\n FROM probe") == "SELECT value FROM probe"
    assert _p95([1, 2, 3, 4, 5]) == 5


def test_postgres_migration_skips_comment_only_statement():
    class Cursor:
        def __init__(self):
            self.statements = []

        def execute(self, statement):
            self.statements.append(statement)

    cursor = Cursor()
    migrate._execute_statements(cursor, "CREATE TABLE x (id INT); -- trailing comment")
    assert cursor.statements == ["CREATE TABLE x (id INT)"]


def test_report_rejects_different_source_versions(tmp_path):
    base = {
        "schema_version": "floci-benchmark-result-v1", "pass": True,
        "profile": "baseline", "seed": 42, "account_id": "111111111111",
        "commit": "abc", "workspace_sha256": "one", "manifest_sha256": "fixture",
        "floci_version": "2.5.0", "floci_image_digest": "sha256:test",
        "expected_counts": {"users": 100}, "db_backend": "sqlite",
        "actual": {"risk_distribution": {"HIGH": 1}},
        "durations_seconds": {"discovery": 1.0}, "peak_rss_bytes": 100,
        "database_bytes": 100,
    }
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    third = tmp_path / "third.json"
    first.write_text(json.dumps(base), encoding="utf-8")
    second.write_text(json.dumps({**base, "workspace_sha256": "two"}), encoding="utf-8")
    third.write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(ValueError, match="workspace_sha256"):
        summarize([first, second, third])
