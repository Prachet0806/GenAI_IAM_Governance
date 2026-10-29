"""Tests for scripts/review.py reviewer CLI."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _seed_db(tmp_path, monkeypatch):
    db_file = tmp_path / "review_test.db"
    monkeypatch.setenv("DB_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("MOCK_IAM", "true")
    from scripts import migrate

    migrate.apply_sqlite()
    from common import repo
    from common.db import db

    with db.get_connection() as conn:
        repo.insert_user(
            conn, "U1", "bob@example.com", "arn:u/bob", "2026-01-01T00:00:00+00:00"
        )
        repo.insert_role(conn, "R-HIGH", "AdministratorAccess", "HIGH")
        repo.insert_role(conn, "R-LOW", "ReadOnlyAccess", "LOW")
        repo.link_user_role(conn, "U1", "R-HIGH")
        repo.link_user_role(conn, "U1", "R-LOW")
        repo.create_campaign(conn, "C1", "test", "2026-01-01T00:00:00+00:00")
        repo.create_review(
            conn, "REV-HIGH", "C1", "U1", "R-HIGH", "2026-01-01T00:00:00+00:00"
        )
        repo.create_review(
            conn, "REV-LOW", "C1", "U1", "R-LOW", "2026-01-01T00:00:00+00:00"
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
