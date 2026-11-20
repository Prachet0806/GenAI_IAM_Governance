"""Durable AI jobs, validated citations, and migrated reviewer consumers."""

import json
import sqlite3
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.review_service import app
from common import ai_artifacts, auth, evidence, repo
from common.db import db
from lambdas.ai_explanation import handler as ai_worker
from lambdas.generate_reviews.handler import generate_campaign
from lambdas.risk_evaluation.handler import evaluate_risk
from reports.export_audit import export_audit_report
from scripts import migrate
from tests.test_evidence_workflow import ACCOUNT_A, _user


@pytest.fixture
def ai_review(tmp_path, monkeypatch):
    path = tmp_path / "ai.db"
    monkeypatch.setenv("DB_URL", f"sqlite:///{path}")
    monkeypatch.setenv("LOCAL_ONLY", "true")
    monkeypatch.setenv("MOCK_IAM", "true")
    monkeypatch.setenv("ENABLE_GENAI", "true")
    monkeypatch.setenv("AI_PROVIDER_DATA_APPROVED", "true")
    monkeypatch.setenv("AI_PSEUDONYM_KEY", "test-only-pseudonym-secret")
    monkeypatch.setenv("GOOGLE_API_KEY", "test-only-provider-key")
    monkeypatch.setenv("REVIEWER_GROUP", "reviewers")
    migrate.apply_sqlite()
    user = _user()
    policy = {
        "PolicyArn": f"arn:aws:iam::{ACCOUNT_A}:policy/Wildcard",
        "PolicyName": "Wildcard",
        "Document": {"Statement": [{
            "Effect": "Allow", "Action": "*", "Resource": "*",
        }]},
        "GrantType": "DIRECT_MANAGED", "SourceId": user["UserId"],
        "SourceName": user["UserName"],
        "AttachmentId": f"arn:aws:iam::{ACCOUNT_A}:policy/Wildcard",
    }
    run_id = "ai-snapshot"
    observed = evidence.grant_observation(ACCOUNT_A, user, policy, run_id)
    with db.get_connection() as conn:
        repo.start_discovery_attempt(
            conn, run_id, datetime.now(timezone.utc).isoformat(),
            "MOCK", ACCOUNT_A, evidence.IAM_USER_POLICY_SCOPE,
        )
        assert repo.publish_discovery_snapshot(
            conn, run_id, ACCOUNT_A, evidence.IAM_USER_POLICY_SCOPE,
            datetime.now(timezone.utc).isoformat(), [user], [observed],
            {"complete_for_declared_scope": True, "coverage": ["test"]},
        )
    evaluate_risk(None, None)
    campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
    with db.get_connection() as conn:
        review_id = conn.execute("SELECT review_id FROM access_reviews WHERE campaign_id=?", (campaign["campaign_id"],)).fetchone()[0]
        repo.assign_campaign_reviewer(conn, campaign["campaign_id"], "assigned", "admin")

    def verify(token):
        if token == "invalid":
            raise auth.AuthenticationError("invalid")
        return {"sub": token, "groups": ["reviewers"]}

    monkeypatch.setattr(auth, "verify_access_token", verify)
    return review_id, path, TestClient(app)


def _auth_get(client, path, token="assigned"):
    return client.get(path, headers={"Authorization": f"Bearer {token}"})


def _auth_post(client, path, payload=None, token="assigned"):
    return client.post(path, json=payload, headers={"Authorization": f"Bearer {token}"})


class _SuccessfulClient:
    def __init__(self, *, bad_citation=False, summary="Wildcard actions warrant manual review."):
        self.prompts = []
        self.bad_citation = bad_citation
        self.summary = summary
        self.models = self

    def generate_content(self, *, model, contents, config):
        self.prompts.append(contents)
        context = json.loads(contents.split("Frozen evidence JSON:\n", 1)[1])
        citation = "fabricated-id" if self.bad_citation else context["risk_assessment_id"]
        class Response:
            usage_metadata = None
        response = Response()
        response.text = json.dumps({
            "summary": self.summary,
            "citations": [citation], "limitations": "Effective access was not evaluated.",
        })
        return response


def test_idempotent_job_validated_projection_and_decision_binding(ai_review, monkeypatch, tmp_path):
    review_id, path, client = ai_review
    fake = _SuccessfulClient()
    monkeypatch.setattr(ai_worker, "_get_client", lambda: fake)
    queued = _auth_post(client, f"/reviews/{review_id}/ai/explanation")
    assert queued.status_code == 202
    assert _auth_post(client, f"/reviews/{review_id}/ai/explanation").json()["job_id"] == queued.json()["job_id"]
    assert _auth_post(client, f"/reviews/{review_id}/ai/explanation", token="outsider").status_code == 403
    result = ai_worker.handler({"review_id": review_id}, None)
    assert result["status"] == "SUCCEEDED"
    assert ai_worker.handler({"review_id": review_id}, None)["status"] == "IDLE"
    assert "alice" not in fake.prompts[0]
    assert "alice@example.com" not in fake.prompts[0]
    review_response = _auth_get(client, f"/reviews/{review_id}").json()
    assert review_response["policy_evidence_status"] == "COMPLETE"
    assert review_response["snapshot_current_eligible"] is True
    projection = review_response["ai_explanation"]
    assert projection["authority"] == "validated_artifact"
    assert projection["validated_artifact"] is True
    assert projection["citations"][0]["kind"] == "grant_risk_assessment"
    assert _auth_get(client, f"/ai/jobs/{queued.json()['job_id']}").json()["status"] == "SUCCEEDED"
    assert _auth_get(client, f"/ai/jobs/{queued.json()['job_id']}", token="outsider").status_code == 403
    decision = _auth_post(client, f"/reviews/{review_id}/decision", {"decision": "APPROVED"})
    assert decision.status_code == 200
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM ai_jobs").fetchone() == (1,)
        assert conn.execute("SELECT COUNT(*) FROM ai_artifacts").fetchone() == (1,)
        assert conn.execute("SELECT COUNT(*) FROM remediation_approvals").fetchone() == (0,)
        assert conn.execute("SELECT ai_artifact_id FROM review_decision_events WHERE review_id=?", (review_id,)).fetchone() == (projection["artifact_id"],)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE ai_artifacts SET output_json='{}'")
    monkeypatch.chdir(tmp_path)
    exported = export_audit_report()
    records = json.loads((tmp_path / exported["json"]).read_text(encoding="utf-8"))
    assert records[0]["ai_artifact_id"] == projection["artifact_id"]
    assert records[0]["decision_events"][0]["ai_artifact_id"] == projection["artifact_id"]
    assert records[0]["decision_events"][0]["reviewer_comment"] == ""
    assert records[0]["decision_events"][0]["decision_origin"] == "OIDC_API"
    assert records[0]["decision_events"][0]["snapshot_id"] == "ai-snapshot"
    assert records[0]["workflow_events"][0]["new_value"] == "OPEN"
    assert records[0]["ai_authority"] == "validated_artifact"


def test_invalid_citation_retries_then_publishes_labelled_fallback(ai_review, monkeypatch):
    review_id, _, client = ai_review
    fake = _SuccessfulClient(bad_citation=True)
    monkeypatch.setattr(ai_worker, "_get_client", lambda: fake)
    for attempt in range(1, 4):
        result = ai_worker.handler({"review_id": review_id}, None)
        assert result["status"] == ("PENDING" if attempt < 3 else "FALLBACK")
        with db.get_connection() as conn:
            conn.execute("UPDATE ai_jobs SET run_after='2000-01-01T00:00:00+00:00' WHERE status='PENDING'")
    explanation = _auth_get(client, f"/reviews/{review_id}").json()["ai_explanation"]
    assert explanation["source"] == "FALLBACK"
    assert explanation["authority"] == "validated_artifact"
    assert _auth_get(client, "/ai/metrics").status_code == 403
    monkeypatch.setenv("CAMPAIGN_ADMIN_GROUP", "reviewers")
    metrics = _auth_get(client, "/ai/metrics")
    assert metrics.status_code == 200
    assert metrics.json()["jobs"]["FALLBACK"] == 1
    with db.get_connection() as conn:
        assert conn.execute("SELECT outcome,COUNT(*) FROM ai_attempts GROUP BY outcome ORDER BY outcome").fetchall() == [
            ("FALLBACK", 1), ("RETRY", 2)
        ]


def test_fallback_cannot_be_blocked_by_action_words_in_rule_reason(ai_review):
    review_id, _, _ = ai_review
    with db.get_connection() as conn:
        context = ai_artifacts.build_context(conn, review_id)
    context["risk_reason"] = "revoke or approve this access"
    output = ai_artifacts.fallback_output(context)
    assert output["citations"] == [context["risk_assessment_id"]]


def test_empty_limitations_are_not_validated(ai_review):
    with pytest.raises(ValueError, match="limitations"):
        ai_artifacts.validate_output({
            "summary": "Review the cited policy risk.",
            "citations": ["assessment"], "limitations": "  ",
        }, ["assessment"])


def test_failed_job_admin_retry_creates_audited_new_generation(ai_review, monkeypatch):
    review_id, _, client = ai_review
    monkeypatch.setenv("CAMPAIGN_ADMIN_GROUP", "campaign-admins")

    def verify(token):
        return {"sub": token, "groups": ["campaign-admins"] if token == "admin" else ["reviewers"]}

    monkeypatch.setattr(auth, "verify_access_token", verify)
    with db.get_connection() as conn:
        first = ai_artifacts.enqueue_review(conn, review_id, pseudonym_key="test-only-pseudonym-secret")
        conn.execute("UPDATE ai_jobs SET max_attempts=1 WHERE job_id=?", (first["job_id"],))
    with db.get_connection() as conn:
        claimed = ai_artifacts.claim_job(conn, job_id=first["job_id"])
    with db.get_connection() as conn:
        assert ai_artifacts.fail_or_retry(conn, claimed, error_code="provider_unavailable", latency_ms=1) == "FAILED"

    path = f"/ai/jobs/{first['job_id']}/retry"
    assert _auth_post(client, path).status_code == 403
    retry = _auth_post(client, path, token="admin")
    assert retry.status_code == 202
    assert retry.json()["generation"] == 2
    assert retry.json()["job_id"] != first["job_id"]
    repeated = _auth_post(client, path, token="admin")
    assert repeated.status_code == 202
    assert repeated.json()["job_id"] == retry.json()["job_id"]
    fake = _SuccessfulClient()
    monkeypatch.setattr(ai_worker, "_get_client", lambda: fake)
    assert ai_worker.handler(None, None)["processed"][0]["status"] == "SUCCEEDED"
    with db.get_connection() as conn:
        assert conn.execute("SELECT retry_of_job_id FROM ai_jobs WHERE job_id=?",
                            (retry.json()["job_id"],)).fetchone() == (first["job_id"],)
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action='ai_job_retry'").fetchone() == (1,)


def test_retries_from_two_models_allocate_distinct_generations(ai_review, monkeypatch):
    review_id, _, _ = ai_review
    for model in ("model-a", "model-b"):
        monkeypatch.setenv("GENAI_MODEL", model)
        with db.get_connection() as conn:
            job = ai_artifacts.enqueue_review(
                conn, review_id, pseudonym_key="test-only-pseudonym-secret"
            )
            conn.execute("UPDATE ai_jobs SET max_attempts=1 WHERE job_id=?",
                         (job["job_id"],))
        with db.get_connection() as conn:
            claimed = ai_artifacts.claim_job(conn, job_id=job["job_id"])
        with db.get_connection() as conn:
            assert ai_artifacts.fail_or_retry(
                conn, claimed, error_code="provider_unavailable", latency_ms=1
            ) == "FAILED"
        if model == "model-a":
            first = job
        else:
            second = job

    with db.get_connection() as conn:
        retried_first = ai_artifacts.retry_failed_job(
            conn, first["job_id"], actor_sub="admin",
            pseudonym_key="test-only-pseudonym-secret",
        )
    with db.get_connection() as conn:
        retried_second = ai_artifacts.retry_failed_job(
            conn, second["job_id"], actor_sub="admin",
            pseudonym_key="test-only-pseudonym-secret",
        )
        assert (retried_first["generation"], retried_second["generation"]) == (2, 3)
        assert retried_first["job_id"] != retried_second["job_id"]
        assert conn.execute(
            "SELECT retry_of_job_id FROM ai_jobs WHERE job_id=?",
            (retried_second["job_id"],),
        ).fetchone() == (second["job_id"],)


def test_model_change_creates_new_job_and_pins_model(ai_review, monkeypatch):
    review_id, _, client = ai_review
    fake = _SuccessfulClient()
    monkeypatch.setattr(ai_worker, "_get_client", lambda: fake)
    assert ai_worker.handler({"review_id": review_id}, None)["status"] == "SUCCEEDED"
    first = _auth_get(client, f"/reviews/{review_id}").json()["ai_explanation"]
    monkeypatch.setenv("GENAI_MODEL", "next-model")
    assert ai_worker.handler({"review_id": review_id}, None)["status"] == "SUCCEEDED"
    latest = _auth_get(client, f"/reviews/{review_id}").json()["ai_explanation"]
    assert latest["model"] == "next-model"
    assert latest["artifact_id"] != first["artifact_id"]
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM ai_jobs").fetchone() == (2,)


def test_expired_worker_cannot_publish_after_lease_reclaimed(ai_review):
    review_id, _, _ = ai_review
    with db.get_connection() as conn:
        ai_artifacts.enqueue_review(conn, review_id, pseudonym_key="test-only-pseudonym-secret")
    with db.get_connection() as conn:
        first = ai_artifacts.claim_job(conn)
    with db.get_connection() as conn:
        conn.execute("UPDATE ai_jobs SET lease_expires_at='2000-01-01T00:00:00+00:00'")
    with db.get_connection() as conn:
        second = ai_artifacts.claim_job(conn)
    assert second["lease_token"] != first["lease_token"]
    with db.get_connection() as conn:
        context = ai_artifacts.build_context(conn, review_id, pseudonym_key="test-only-pseudonym-secret")
        output = ai_artifacts.fallback_output(context)
        assert not ai_artifacts.complete_job(conn, first, output, source="FALLBACK", provider=None, model=None, latency_ms=1)
    with db.get_connection() as conn:
        assert ai_artifacts.complete_job(conn, second, output, source="FALLBACK", provider=None, model=None, latency_ms=1)
        assert conn.execute("SELECT COUNT(*) FROM ai_artifacts").fetchone() == (1,)


def test_old_summary_and_missing_output_remain_explicit_compatibility(ai_review, tmp_path, monkeypatch):
    review_id, _, client = ai_review
    monkeypatch.chdir(tmp_path)
    missing = _auth_get(client, f"/reviews/{review_id}").json()["ai_explanation"]
    assert missing["status"] == "missing"
    missing_report = export_audit_report()
    missing_record = json.loads((tmp_path / missing_report["json"]).read_text(encoding="utf-8"))[0]
    assert missing_record["ai_summary"] is None
    assert missing_record["ai_authority"] == "legacy_compatibility"
    with db.get_connection() as conn:
        conn.execute("UPDATE access_reviews SET ai_risk_summary='historic text' WHERE review_id=?", (review_id,))
    old = _auth_get(client, f"/reviews/{review_id}").json()["ai_explanation"]
    assert old["authority"] == "legacy_compatibility"
    assert old["validated_artifact"] is False
    assert old["summary"] == "historic text"
    old_report = export_audit_report()
    old_record = json.loads((tmp_path / old_report["json"]).read_text(encoding="utf-8"))[0]
    assert old_record["ai_summary"] == "historic text"
    assert old_record["ai_validated_artifact"] is False


def test_latest_validated_generation_is_authoritative_over_legacy(ai_review, monkeypatch, tmp_path):
    review_id, _, client = ai_review
    with db.get_connection() as conn:
        conn.execute("UPDATE access_reviews SET ai_risk_summary='historic text' WHERE review_id=?", (review_id,))
    first = _SuccessfulClient(summary="First validated explanation.")
    monkeypatch.setattr(ai_worker, "_get_client", lambda: first)
    assert ai_worker.handler({"review_id": review_id}, None)["status"] == "SUCCEEDED"
    previous = _auth_get(client, f"/reviews/{review_id}").json()["ai_explanation"]
    assert previous["summary"] == "First validated explanation."
    monkeypatch.setattr(ai_artifacts, "PROMPT_VERSION", "review-explanation-v5-test")
    second = _SuccessfulClient(summary="Second validated explanation.")
    monkeypatch.setattr(ai_worker, "_get_client", lambda: second)
    assert ai_worker.handler({"review_id": review_id}, None)["status"] == "SUCCEEDED"
    current = _auth_get(client, f"/reviews/{review_id}").json()["ai_explanation"]
    assert current["summary"] == "Second validated explanation."
    assert current["artifact_id"] != previous["artifact_id"]
    assert current["authority"] == "validated_artifact"
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM ai_artifacts").fetchone() == (2,)
    monkeypatch.chdir(tmp_path)
    exported = export_audit_report()
    record = json.loads((tmp_path / exported["json"]).read_text(encoding="utf-8"))[0]
    assert record["ai_summary"] == "Second validated explanation."
    assert record["ai_artifact_id"] == current["artifact_id"]
