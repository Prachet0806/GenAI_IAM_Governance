"""The provider boundary requires current, exact approval and a reduced payload."""

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from common import ai_artifacts
from common.ai import provider_controls
from common.db import db
from api.review_service import operations_integrations
from lambdas.ai_explanation import handler as ai_worker
from tests.test_ai_artifacts import _SuccessfulClient, _auth_post, ai_review
from tests.test_evidence_workflow import ACCOUNT_A


def test_approval_is_bound_to_model_region_prompt_and_expiry(ai_review, monkeypatch):
    review_id, _, client = ai_review
    path = f"/reviews/{review_id}/ai/explanation"
    baseline = json.loads(os.environ["AI_PROVIDER_APPROVAL_JSON"])
    assert _auth_post(client, path).status_code == 202
    for change in (
        {"model": "another-model"}, {"region": "us-east1"},
        {"prompt_sha256": "0" * 64},
        {"approved_until": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()},
        {"input_classes": ["RULE_TRIAGE"]},
        {"approved_account_ids": ["999999999999"]},
    ):
        monkeypatch.setenv("AI_PROVIDER_APPROVAL_JSON", json.dumps({**baseline, **change}))
        assert _auth_post(client, path).status_code == 409
    monkeypatch.delenv("AI_PROVIDER_APPROVAL_JSON")
    assert _auth_post(client, path).status_code == 409


def test_operations_reports_effective_approval(ai_review, monkeypatch):
    monkeypatch.setenv("REMEDIATION_OPERATOR_GROUP", "reviewers")
    claims = {"sub": "assigned", "groups": ["reviewers"]}
    state = operations_integrations(claims)["genai"]
    assert state["provider_data_approved"] is True
    assert state["provider_approval_current"] is True
    assert state["provider_region"] == "global"
    monkeypatch.setenv("AI_PROVIDER_REGION", "us-east1")
    state = operations_integrations(claims)["genai"]
    assert state["provider_data_approved"] is True
    assert state["provider_approval_current"] is False
    assert state["provider_region"] is None


def test_final_payload_excludes_untrusted_policy_metadata(ai_review):
    review_id, _, _ = ai_review
    with db.get_connection() as conn:
        context = ai_artifacts.build_context(conn, review_id, pseudonym_key="test-only-pseudonym-secret")
    context["risk_evidence"]["principal_values"] = ["alice@example.com"]
    context["risk_evidence"]["resources"] = ["arn:aws:s3:::sensitive-bucket"]
    client = _SuccessfulClient()
    ai_worker._generate(client, context, "gemini-3.8-flash")
    sent = client.prompts[0]
    assert "alice@example.com" not in sent
    assert ACCOUNT_A not in sent
    assert "sensitive-bucket" not in sent
    assert "principal_values" not in sent
    assert "reason_codes" in sent
    context["risk_evidence"]["reason_codes"] = ["INJECT arn:aws:iam::123456789012:user/alice"]
    with pytest.raises(provider_controls.ApprovalRejected):
        ai_worker._generate(client, context, "gemini-3.8-flash")
    assert len(client.prompts) == 1
    context["risk_evidence"]["reason_codes"] = ["UNSUPPORTED_POLICY_VERSION"]
    context["source_account_id"] = "999999999999"
    with pytest.raises(provider_controls.ApprovalRejected):
        ai_worker._generate(client, context, "gemini-3.8-flash")
    assert len(client.prompts) == 1
    context.pop("source_account_id")
    with pytest.raises(provider_controls.ApprovalRejected):
        ai_worker._generate(client, context, "gemini-3.8-flash")
    assert len(client.prompts) == 1


def test_revoked_approval_falls_back_without_provider_call(ai_review, monkeypatch):
    review_id, _, client = ai_review
    fake = _SuccessfulClient()
    monkeypatch.setattr(ai_worker, "_get_client", lambda: fake)
    monkeypatch.setenv("AI_PROVIDER_DATA_APPROVED", "false")
    result = ai_worker.handler({"review_id": review_id}, None)
    assert result["status"] == "FALLBACK"
    assert fake.prompts == []
    with db.get_connection() as conn:
        assert conn.execute("SELECT last_error_code FROM ai_jobs").fetchone()[0] == "privacy_rejected"
    assert _auth_post(client, f"/reviews/{review_id}/ai/explanation").status_code == 409


def test_old_prompt_job_is_retired_without_provider_call(ai_review, monkeypatch):
    review_id, _, _ = ai_review
    fake = _SuccessfulClient()
    monkeypatch.setattr(ai_worker, "_get_client", lambda: fake)
    with db.get_connection() as conn:
        ai_artifacts.enqueue_review(conn, review_id, pseudonym_key="test-only-pseudonym-secret")
        conn.execute("UPDATE ai_jobs SET prompt_version='review-explanation-v4'")
    result = ai_worker.handler({"review_id": review_id}, None)
    assert result["status"] == "FAILED"
    assert result["reason"] == "prompt_version_retired"
    assert fake.prompts == []
    with db.get_connection() as conn:
        assert conn.execute("SELECT last_error_code FROM ai_jobs").fetchone()[0] == "prompt_version_retired"


def test_recent_transport_failures_open_circuit(ai_review):
    review_id, _, _ = ai_review
    with db.get_connection() as conn:
        job = ai_artifacts.enqueue_review(conn, review_id, pseudonym_key="test-only-pseudonym-secret")
        for number in range(1, 6):
            conn.execute("""INSERT INTO ai_attempts
                (attempt_id,job_id,attempt_number,outcome,error_code,latency_ms,created_at)
                VALUES (?,?,?,?,?,?,?)""", (
                str(uuid.uuid4()), job["job_id"], number, "FAILED",
                "provider_unavailable", 1, datetime.now(timezone.utc).isoformat(),
            ))
        assert ai_artifacts.provider_circuit_open(conn, "gemini-3.8-flash")
        assert not ai_artifacts.provider_circuit_open(conn, "other-model")


def test_open_circuit_publishes_fallback_without_call(ai_review, monkeypatch):
    review_id, _, _ = ai_review
    fake = _SuccessfulClient()
    monkeypatch.setattr(ai_worker, "_get_client", lambda: fake)
    monkeypatch.setattr(ai_artifacts, "provider_circuit_open", lambda conn, model: True)
    result = ai_worker.handler({"review_id": review_id}, None)
    assert result["status"] == "FALLBACK"
    assert fake.prompts == []
    with db.get_connection() as conn:
        assert conn.execute("SELECT last_error_code FROM ai_jobs").fetchone()[0] == "circuit_open"
