"""Campaign state, queue authorization, and append-only workflow history."""

import json
import sqlite3
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.review_service import app
from common import auth, repo, workflow
from common.db import db
from reports.export_audit import export_audit_report
from scripts import migrate


def _setup(tmp_path, monkeypatch):
    path = tmp_path / "workflow.db"
    monkeypatch.setenv("DB_URL", f"sqlite:///{path}")
    monkeypatch.setenv("REVIEWER_GROUP", "reviewers")
    monkeypatch.setenv("CAMPAIGN_ADMIN_GROUP", "campaign-admins")
    migrate.apply_sqlite()
    with db.get_connection() as conn:
        repo.insert_user(conn, "U1", "alice", "arn:aws:iam::123:user/alice", "2026-01-01T00:00:00+00:00")
        for index in (1, 2):
            repo.insert_role(conn, f"R{index}", f"Policy{index}", "HIGH")
            repo.create_campaign(conn, f"C{index}", f"Campaign{index}", "2026-01-01T00:00:00+00:00")
            repo.create_review(conn, f"REV{index}", f"C{index}", "U1", f"R{index}", "2026-01-01T00:00:00+00:00")
        repo.assign_campaign_reviewer(conn, "C1", "alice", "admin")
        repo.assign_campaign_reviewer(conn, "C1", "bob", "admin")
        repo.assign_campaign_reviewer(conn, "C2", "charlie", "admin")

    def verify(token):
        if token == "bad":
            raise auth.AuthenticationError("invalid")
        return {
            "sub": token,
            "groups": ["campaign-admins"] if token == "admin" else ["reviewers"],
        }

    monkeypatch.setattr(auth, "verify_access_token", verify)
    return TestClient(app), path


def _request(client, method, path, token, payload=None):
    return client.request(
        method, path, headers={"Authorization": f"Bearer {token}"}, json=payload
    )


def test_queue_assignment_and_cross_campaign_isolation(tmp_path, monkeypatch):
    client, _ = _setup(tmp_path, monkeypatch)
    assert [row["review_id"] for row in _request(client, "GET", "/reviews/queue", "alice").json()["reviews"]] == ["REV1"]
    assert _request(client, "GET", "/reviews/REV2", "alice").status_code == 403
    assert _request(client, "POST", "/reviews/REV1/assignment", "alice", {"reviewer_sub": "bob"}).status_code == 403
    assert _request(client, "POST", "/reviews/REV1/assignment", "admin", {"reviewer_sub": "charlie"}).status_code == 422
    assigned = _request(client, "POST", "/reviews/REV1/assignment", "admin", {"reviewer_sub": "bob"})
    assert assigned.status_code == 200
    assert _request(client, "GET", "/reviews/queue", "alice").json()["reviews"] == []
    assert _request(client, "GET", "/reviews/REV1", "alice").status_code == 403
    assert _request(client, "POST", "/reviews/REV1/decision", "alice", {"decision": "APPROVED"}).status_code == 403
    assert _request(client, "GET", "/reviews/REV1", "bob").status_code == 200
    events = _request(client, "GET", "/campaigns/C1/events", "bob").json()["events"]
    assert events[0]["event_type"] == "REVIEW_ASSIGNED"
    assert _request(client, "GET", "/campaigns/C2/events", "bob").status_code == 403
    monkeypatch.setenv("LOCAL_ONLY", "true")
    monkeypatch.chdir(tmp_path)
    exported = export_audit_report()
    records = json.loads((tmp_path / exported["json"]).read_text(encoding="utf-8"))
    assigned_event = next(event for row in records if row["review_id"] == "REV1"
                          for event in row["workflow_events"]
                          if event["event_type"] == "REVIEW_ASSIGNED")
    assert assigned_event["previous_value"] is None
    assert assigned_event["new_value"] == "bob"


def test_frontend_identity_queue_filters_summary_and_account_scope(tmp_path, monkeypatch):
    client, _ = _setup(tmp_path, monkeypatch)

    identity = _request(client, "GET", "/me", "alice").json()
    assert identity["subject"] == "alice"
    assert identity["roles"] == ["reviewer"]
    assert identity["scope_mode"] == "global_admin"

    summary = _request(client, "GET", "/reviews/summary", "alice").json()
    assert summary["assigned"] == 1
    assert summary["pending"] == 1
    filtered = _request(
        client, "GET", "/reviews/queue?status=ALL&principal=missing", "alice"
    ).json()
    assert filtered["reviews"] == []
    assert filtered["total"] == 0
    assert filtered["has_more"] is False

    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "aws_account_scopes")
    monkeypatch.setattr(
        auth, "verify_access_token",
        lambda token: {"sub": token, "groups": ["reviewers"], "aws_account_scopes": ["123456789012"]},
    )
    scoped_identity = _request(client, "GET", "/me", "alice").json()
    assert scoped_identity["scope_mode"] == "claim"
    assert scoped_identity["account_scopes"] == ["123456789012"]
    scoped_queue = _request(client, "GET", "/reviews/queue", "alice").json()
    assert scoped_queue["reviews"] == []
    assert scoped_queue["total"] == 0


def test_exception_blocks_decision_and_campaign_close_until_resolved(tmp_path, monkeypatch):
    client, path = _setup(tmp_path, monkeypatch)
    opened = _request(client, "POST", "/reviews/REV1/exception", "alice", {"reason": "Manager review needed"})
    assert opened.status_code == 200
    assert _request(client, "POST", "/reviews/REV1/decision", "alice", {"decision": "APPROVED"}).status_code == 409
    assert _request(client, "POST", "/campaigns/C1/state", "admin", {"state": "CLOSED"}).status_code == 409
    assert _request(client, "POST", "/reviews/REV1/exception/resolve", "alice", {"reason": "Done"}).status_code == 403
    assert _request(client, "POST", "/reviews/REV1/exception/resolve", "admin", {"reason": "Verified"}).status_code == 200
    assert _request(client, "POST", "/campaigns/C1/state", "admin", {"state": "PAUSED"}).status_code == 200
    assert _request(client, "POST", "/reviews/REV1/decision", "alice", {"decision": "APPROVED"}).status_code == 409
    assert [row["review_id"] for row in _request(client, "GET", "/reviews/queue", "alice").json()["reviews"]] == ["REV1"]
    assert _request(client, "POST", "/campaigns/C1/state", "admin", {"state": "OPEN"}).status_code == 200
    assert _request(client, "POST", "/reviews/REV1/decision", "alice", {"decision": "APPROVED"}).status_code == 200
    assert _request(client, "POST", "/campaigns/C1/state", "admin", {"state": "CLOSED"}).status_code == 200
    assert _request(client, "POST", "/campaigns/C1/state", "admin", {"state": "OPEN"}).status_code == 409
    assert [row["review_id"] for row in _request(client, "GET", "/reviews/queue?status=ALL", "alice").json()["reviews"]] == ["REV1"]
    with sqlite3.connect(path) as conn:
        event_id = conn.execute("SELECT event_id FROM review_workflow_events LIMIT 1").fetchone()[0]
        try:
            conn.execute("UPDATE review_workflow_events SET actor_sub='changed' WHERE event_id=?", (event_id,))
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("Workflow history was mutable")


def test_campaign_ownership_scope_deadlines_and_invalid_transitions(tmp_path, monkeypatch):
    client, _ = _setup(tmp_path, monkeypatch)
    assert _request(client, "POST", "/campaigns/C1/state", "admin", {"state": "OPEN"}).status_code == 409
    assert _request(client, "POST", "/campaigns/C1/owner", "admin", {"owner_sub": "owner"}).status_code == 200
    assert _request(client, "POST", "/campaigns/C1/deadline", "admin", {"due_at": "2030-01-01T00:00:00"}).status_code == 422
    assert _request(client, "POST", "/campaigns/C1/deadline", "admin", {"due_at": "2030-01-01T00:00:00+00:00"}).status_code == 200
    assert _request(client, "POST", "/reviews/REV1/deadline", "admin", {"due_at": "2030-01-02T00:00:00+00:00"}).status_code == 200
    item = _request(client, "GET", "/campaigns/C1", "alice").json()
    assert item["owner_sub"] == "owner"
    assert item["due_at"].startswith("2030-01-01")
    assert _request(client, "GET", "/campaigns/C2", "alice").status_code == 403
    first_page = _request(client, "GET", "/campaigns/C1/events?limit=1&offset=0", "admin")
    second_page = _request(client, "GET", "/campaigns/C1/events?limit=1&offset=1", "admin")
    assert first_page.status_code == second_page.status_code == 200
    assert len(first_page.json()["events"]) == len(second_page.json()["events"]) == 1
    assert first_page.json()["events"][0]["event_id"] != second_page.json()["events"][0]["event_id"]
    assert _request(client, "GET", "/campaigns/C1/events?limit=0", "admin").status_code == 422


def test_queue_repository_limits_and_preserves_pool_access(tmp_path, monkeypatch):
    client, _ = _setup(tmp_path, monkeypatch)
    with db.get_connection() as conn:
        assert len(workflow.queue(conn, "alice", limit=1)) == 1
        assert workflow.queue(conn, "outsider") == []
    assert _request(client, "GET", "/reviews/queue?limit=1&offset=0", "alice").json()["reviews"][0]["review_id"] == "REV1"
    assert _request(client, "GET", "/reviews/queue?limit=1&offset=1", "alice").json()["reviews"] == []
    assert _request(client, "GET", "/reviews/queue?limit=0", "alice").status_code == 422


def test_campaign_reviewer_assignment_validates_subject_and_records_event(tmp_path, monkeypatch):
    client, _ = _setup(tmp_path, monkeypatch)
    assert _request(client, "POST", "/campaigns/C1/reviewers", "admin", {"reviewer_sub": "  "}).status_code == 422
    assigned = _request(client, "POST", "/campaigns/C1/reviewers", "admin", {"reviewer_sub": " dave "})
    assert assigned.status_code == 201
    assert assigned.json()["reviewer_sub"] == "dave"
    assert _request(client, "GET", "/reviews/queue", "dave").status_code == 200
    assert [row["review_id"] for row in _request(client, "GET", "/reviews/queue", "dave").json()["reviews"]] == ["REV1"]
    events = _request(client, "GET", "/campaigns/C1/events", "admin").json()["events"]
    assert events[0]["event_type"] == "CAMPAIGN_REVIEWER_ADDED"
    assert events[0]["new_value"] == "dave"


def test_operations_audit_applies_operator_account_scope(tmp_path, monkeypatch):
    from datetime import datetime, timezone

    client, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setenv("REMEDIATION_OPERATOR_GROUP", "operators")
    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "aws_account_scopes")
    monkeypatch.setattr(auth, "verify_access_token", lambda token: {
        "sub": token, "groups": ["operators"],
        "aws_account_scopes": ["123456789012"],
    })
    with db.get_connection() as conn:
        db.execute(conn.cursor(), "UPDATE campaigns SET account_id=? WHERE campaign_id=?",
                   ("123456789012", "C1"))
        db.execute(conn.cursor(), "UPDATE campaigns SET account_id=? WHERE campaign_id=?",
                   ("999999999999", "C2"))
        repo.insert_audit_log(
            conn, "AUDIT-C1", datetime.now(timezone.utc), "INFO", "campaign_update",
            "success", "Scoped event", entity_type="campaign", entity_id="C1",
        )
        repo.insert_audit_log(
            conn, "AUDIT-C2", datetime.now(timezone.utc), "INFO", "campaign_update",
            "success", "Out-of-scope event", entity_type="campaign", entity_id="C2",
        )
    response = _request(client, "GET", "/operations/audit", "operator")
    assert response.status_code == 200
    assert [event["event_id"] for event in response.json()["events"]] == ["AUDIT-C1"]
