"""Campaign state, queue authorization, and append-only workflow history."""

import json
import sqlite3
import sys
from pathlib import Path

import pytest
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
        if token == "outsider":
            groups = ["reviewers"]
        elif token == "dual_admin":
            groups = ["reviewers", "campaign-admins"]
        elif token == "admin":
            groups = ["campaign-admins"]
        else:
            groups = ["reviewers"]
        return {
            "sub": token,
            "groups": groups,
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
    invalid_assignment = _request(client, "POST", "/reviews/REV1/assignment", "admin", {"reviewer_sub": "charlie"})
    assert invalid_assignment.status_code == 422, invalid_assignment.text
    assigned = _request(client, "POST", "/reviews/REV1/assignment", "admin", {"reviewer_sub": "bob"})
    assert assigned.status_code == 200
    assert _request(client, "GET", "/reviews/queue", "alice").json()["reviews"] == []
    assert _request(client, "GET", "/reviews/REV1", "alice").status_code == 403
    assert _request(client, "POST", "/reviews/REV1/decision", "alice", {"decision": "APPROVED"}).status_code == 403
    bob_review = _request(client, "GET", "/reviews/REV1", "bob")
    assert bob_review.status_code == 200
    assert bob_review.json()["can_decide"] is True
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


def test_account_scope_fails_closed_and_accepts_explicit_scopes(monkeypatch):
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "account_scopes")
    monkeypatch.setenv("OIDC_ALLOW_GLOBAL_SCOPE", "true")

    one = auth.identity_summary({"sub": "user", "account_scopes": "123456789012"})
    assert one["account_scopes"] == ["123456789012"]
    auth.require_account_scope({"sub": "user", "account_scopes": ["123456789012"]}, "123456789012")
    with pytest.raises(auth.AuthorizationError):
        auth.require_account_scope({"sub": "user", "account_scopes": ["123456789012"]}, "999999999999")

    multiple = auth.identity_summary({"sub": "user", "account_scopes": ["999999999999", "123456789012"]})
    assert multiple["account_scopes"] == ["123456789012", "999999999999"]
    wildcard = {"sub": "user", "account_scopes": ["*"]}
    auth.require_account_scope(wildcard, "999999999999")

    for bad_claim in (None, [], [""], ["not-an-account"], ["*", "123456789012"], [123]):
        claims = {"sub": "user"}
        if bad_claim is not None:
            claims["account_scopes"] = bad_claim
        assert auth.identity_summary(claims)["account_scopes"] == []
        with pytest.raises(auth.AuthorizationError):
            auth.require_account_scope(claims, "123456789012")

    monkeypatch.delenv("OIDC_ACCOUNT_SCOPE_CLAIM", raising=False)
    monkeypatch.setenv("OIDC_ALLOW_GLOBAL_SCOPE", "false")
    unconfigured = {"sub": "user"}
    assert auth.identity_summary(unconfigured)["scope_mode"] == "unconfigured"
    with pytest.raises(auth.AuthorizationError):
        auth.require_account_scope(unconfigured, "123456789012")


def test_shared_environment_requires_account_scope_claim(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("OIDC_ACCOUNT_SCOPE_CLAIM", raising=False)
    with pytest.raises(RuntimeError, match="OIDC_ACCOUNT_SCOPE_CLAIM"):
        auth.validate_account_scope_configuration()
    with pytest.raises(RuntimeError, match="OIDC_ACCOUNT_SCOPE_CLAIM"):
        with TestClient(app):
            pass


def test_api_rejects_missing_empty_and_malformed_account_scope_claims(tmp_path, monkeypatch):
    client, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "account_scopes")

    def verify(token):
        claims = {"sub": token, "groups": ["reviewers"]}
        if token == "valid":
            claims["account_scopes"] = ["123456789012"]
        elif token == "empty":
            claims["account_scopes"] = []
        elif token == "malformed":
            claims["account_scopes"] = ["not-an-account"]
        return claims

    monkeypatch.setattr(auth, "verify_access_token", verify)
    assert _request(client, "GET", "/me", "missing").status_code == 403
    assert _request(client, "GET", "/me", "empty").status_code == 403
    assert _request(client, "GET", "/me", "malformed").status_code == 403
    valid = _request(client, "GET", "/me", "valid")
    assert valid.status_code == 200
    assert valid.json()["account_scopes"] == ["123456789012"]


def test_review_detail_returns_authoritative_decision_eligibility(tmp_path, monkeypatch):
    client, _ = _setup(tmp_path, monkeypatch)
    # A campaign-pool reviewer can decide an unassigned item.
    pool = _request(client, "GET", "/reviews/REV1", "alice").json()
    assert pool["can_decide"] is True
    assert pool["can_decide_reason"] is None

    # A dual-role campaign administrator still needs reviewer-pool membership.
    admin = _request(client, "GET", "/reviews/REV1", "dual_admin").json()
    assert admin["can_decide"] is False
    assert admin["can_decide_reason"] == "CAMPAIGN_MEMBERSHIP_REQUIRED"

    # Membership does not override an individual assignment to someone else.
    with db.get_connection() as conn:
        repo.assign_campaign_reviewer(conn, "C1", "dual_admin", "admin")
        workflow.assign_review(conn, "REV1", "bob", "admin")
    assigned_elsewhere = _request(client, "GET", "/reviews/REV1", "dual_admin").json()
    assert assigned_elsewhere["can_decide"] is False
    assert assigned_elsewhere["can_decide_reason"] == "ASSIGNED_TO_ANOTHER_REVIEWER"

    # A nonmember reviewer cannot read a review to infer its evidence or eligibility.
    assert _request(client, "GET", "/reviews/REV1", "outsider").status_code == 403
    assert _request(client, "POST", "/reviews/REV1/decision", "outsider", {"decision": "APPROVED"}).status_code == 403


def test_shared_environment_blocks_unverified_reviewer_assignments(tmp_path, monkeypatch):
    client, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "account_scopes")
    monkeypatch.setattr(auth, "verify_access_token", lambda token: {
        "sub": token, "groups": ["campaign-admins"], "account_scopes": ["*"]
    })
    monkeypatch.setenv("OIDC_ALLOW_UNVERIFIED_REVIEWER_ASSIGNMENTS", "true")
    response = _request(client, "POST", "/campaigns/C1/reviewers", "admin", {"reviewer_sub": "dave"})
    assert response.status_code == 503
    assert "identity-provider directory verification" in response.json()["error"]["message"]
    reassignment = _request(client, "POST", "/reviews/REV1/assignment", "admin", {"reviewer_sub": "bob"})
    assert reassignment.status_code == 503


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
    assert first_page.json()["total"] >= 2
    assert first_page.json()["has_more"] is True
    assert second_page.json()["offset"] == 1
    assert _request(client, "GET", "/campaigns/C1/events?limit=0", "admin").status_code == 422


def test_queue_repository_limits_and_preserves_pool_access(tmp_path, monkeypatch):
    client, _ = _setup(tmp_path, monkeypatch)
    with db.get_connection() as conn:
        assert len(workflow.queue(conn, "alice", limit=1)) == 1
        assert workflow.queue(conn, "outsider") == []
    assert _request(client, "GET", "/reviews/queue?limit=1&offset=0", "alice").json()["reviews"][0]["review_id"] == "REV1"
    assert _request(client, "GET", "/reviews/queue?limit=1&offset=1", "alice").json()["reviews"] == []
    assert _request(client, "GET", "/reviews/queue?limit=0", "alice").status_code == 422
    assert _request(client, "GET", "/reviews/queue?sort_by=risk", "alice").status_code == 200
    assert _request(client, "GET", "/reviews/queue?sort_by=arbitrary_sql", "alice").status_code == 422


def test_audit_event_type_filter_returns_only_matching_events(tmp_path, monkeypatch):
    client, _ = _setup(tmp_path, monkeypatch)
    assigned = _request(client, "POST", "/campaigns/C1/reviewers", "admin", {"reviewer_sub": "dave"})
    assert assigned.status_code == 201
    all_events = _request(client, "GET", "/audit/events", "admin")
    assert all_events.status_code == 200
    assert all_events.json()["events"]
    filtered = _request(client, "GET", "/audit/events?event_type=NOT_A_REAL_EVENT", "admin")
    assert filtered.status_code == 200
    assert filtered.json()["events"] == []


def test_audit_aggregation_includes_campaign_events_past_old_fetch_cap(
    tmp_path, monkeypatch
):
    from common import workspaces

    _setup(tmp_path, monkeypatch)
    with db.get_connection() as conn:
        db.executemany(
            conn.cursor(),
            """INSERT INTO review_workflow_events
               (event_id,campaign_id,review_id,event_type,actor_sub,
                previous_value,new_value,details,created_at)
               VALUES (?,? ,NULL,?,?,NULL,NULL,'{}',?)""",
            [
                (f"BULK-{index:04d}", "C1", "BULK_EVENT", "admin", "2000-01-01T00:00:00+00:00")
                for index in range(1001)
            ],
        )
        result = workspaces.audit_events(
            conn, None, campaign_id="C1", limit=50, offset=1000
        )

    assert result["total"] >= 1001
    assert any(event["event_id"] == "BULK-0000" for event in result["events"])


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
