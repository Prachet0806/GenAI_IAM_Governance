"""Staging-only path actions, immutable approval evidence, and crash recovery."""

import sqlite3
import uuid

import pytest
from fastapi import Response

from api import review_service
from common import repo
from common.db import db
from lambdas.generate_reviews.handler import generate_campaign
from lambdas.remediation import handler as remediation
from lambdas.risk_evaluation.handler import evaluate_risk
from reports.export_audit import export_audit_report
from scripts import migrate
from tests.test_evidence_workflow import ACCOUNT_A, POLICY_ARN, READ_POLICY, _publish, _user


@pytest.fixture
def prepared_review(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'remediation.db'}")
    monkeypatch.setenv("LOCAL_ONLY", "true")
    monkeypatch.setenv("REVIEWER_GROUP", "reviewers")
    monkeypatch.setenv("REMEDIATION_APPROVER_GROUP", "approvers")
    migrate.apply_sqlite()

    def create(grant_type="DIRECT_MANAGED"):
        user = _user()
        if grant_type == "DIRECT_MANAGED":
            policy = {
                "PolicyArn": POLICY_ARN, "PolicyName": "Reader",
                "Document": READ_POLICY, "PolicyVersion": "v1",
                "GrantType": grant_type, "SourceId": user["UserId"],
                "SourceName": user["UserName"], "AttachmentId": POLICY_ARN,
            }
        else:
            policy = {
                "PolicyName": f"{user['UserName']}:InlineReader",
                "Document": READ_POLICY, "GrantType": grant_type,
                "SourceId": user["UserId"], "SourceName": user["UserName"],
                "AttachmentId": "InlineReader",
            }
        snapshot_id, _ = _publish(policies=[policy])
        evaluate_risk(None, None)
        campaign = generate_campaign({"account_id": ACCOUNT_A}, None)
        with db.get_connection() as conn:
            review_id = conn.execute(
                "SELECT review_id FROM access_reviews WHERE campaign_id=?",
                (campaign["campaign_id"],),
            ).fetchone()[0]
            repo.assign_campaign_reviewer(
                conn, campaign["campaign_id"], "reviewer", "admin"
            )
        review_service.decide_review(
            review_id,
            review_service.DecisionRequest(
                decision="REVOKED", comment="Remove this exact path"
            ),
            {"sub": "reviewer", "groups": ["reviewers"]},
        )
        approval = review_service.approve_remediation(
            review_id, Response(), {"sub": "approver", "groups": ["approvers"]}
        )
        assert approval["action_type"] == repo.REMEDIATION_ACTIONS[grant_type]
        with db.get_connection() as conn:
            assert repo.is_remediation_approved(conn, review_id, snapshot_id)
        monkeypatch.setenv("MOCK_IAM", "false")
        monkeypatch.setenv("DRY_RUN", "false")
        monkeypatch.setenv("ENABLE_REMEDIATION", "true")
        monkeypatch.setenv("ALLOW_LIVE_REMEDIATION", "true")
        monkeypatch.setenv(
            "REMEDIATION_ALLOWLIST",
            "Reader" if grant_type == "DIRECT_MANAGED"
            else f"{user['UserName']}:InlineReader",
        )
        monkeypatch.setenv("AWS_ACCOUNT_ID", ACCOUNT_A)
        monkeypatch.setenv(
            "STAGING_REMEDIATION_ACCEPTANCE_ID", "test-staging-acceptance"
        )
        monkeypatch.setenv("APP_ENV", "staging")
        return review_id

    return create


class FakeIam:
    def __init__(self, *, inline=False, document=None, crash=False, remains=False):
        self.inline = inline
        self.document = document or READ_POLICY
        self.present = True
        self.crash = crash
        self.remains = remains
        self.actions = 0

    def get_user(self, **kwargs):
        return {"User": {"UserId": _user()["UserId"], "Arn": _user()["Arn"]}}

    def get_paginator(self, operation):
        owner = self

        class Paginator:
            def paginate(self, **kwargs):
                if operation == "list_user_policies":
                    return [{"PolicyNames": ["InlineReader"] if owner.present else []}]
                assert operation == "list_attached_user_policies"
                return [{"AttachedPolicies": [
                    {"PolicyArn": POLICY_ARN}
                ] if owner.present else []}]

        return Paginator()

    def get_policy(self, **kwargs):
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, **kwargs):
        return {"PolicyVersion": {"Document": self.document}}

    def get_user_policy(self, **kwargs):
        return {"PolicyDocument": self.document}

    def _act(self):
        self.actions += 1
        if not self.remains:
            self.present = False
        if self.crash:
            self.crash = False
            raise RuntimeError("simulated response loss after AWS action")

    def detach_user_policy(self, **kwargs):
        assert not self.inline
        self._act()

    def delete_user_policy(self, **kwargs):
        assert self.inline
        self._act()


def test_inline_policy_delete_has_exact_path_evidence(
    prepared_review, monkeypatch, tmp_path
):
    review_id = prepared_review("DIRECT_INLINE")
    fake = FakeIam(inline=True)
    monkeypatch.setattr(remediation, "_get_iam_client", lambda: fake)
    result = remediation.remediate_access(None, None)
    assert result["remediated"] == 1
    assert fake.actions == 1
    with db.get_connection() as conn:
        history = repo.remediation_history(conn, review_id)
        assert [e["event_type"] for e in history["approval_events"]] == ["APPROVED"]
        assert [e["event_type"] for e in history["action_events"]] == [
            "PREFLIGHT_PASSED", "ACTION_REQUESTED", "ACTION_VERIFIED"
        ]
        assert history["action_events"][-1]["evidence"][
            "principal_access_status"
        ] == "not_evaluated"
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM remediation_approval_events")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE remediation_action_events SET actor_id='x'")
        binding = repo.review_evidence_binding(conn, review_id)
        with pytest.raises(RuntimeError, match="current worker lease"):
            repo.record_remediation_action_event(
                conn, attempt_id=str(uuid.uuid4()), review_id=review_id,
                approval_event_id=history["approval_events"][0]["event_id"],
                event_type="PREFLIGHT_REJECTED",
                action_type=repo.REMEDIATION_ACTIONS[binding["grant_type"]],
                actor_id="stale-worker", binding=binding, claim_token="stale",
                fencing_token=1, evidence_data={"reason": "stale"},
            )
    from fastapi import HTTPException

    visible = review_service.get_remediation_history(
        review_id, {"sub": "approver", "groups": ["approvers"]}
    )
    assert len(visible["action_events"]) == 3
    with pytest.raises(HTTPException) as denied:
        review_service.get_remediation_history(
            review_id, {"sub": "stranger", "groups": []}
        )
    assert denied.value.status_code == 403
    monkeypatch.chdir(tmp_path)
    result = export_audit_report()
    import json
    record = json.loads((tmp_path / result["json"]).read_text(encoding="utf-8"))[0]
    assert record["remediation_approval_events"][0]["event_type"] == "APPROVED"
    assert record["remediation_action_events"][-1]["event_type"] == "ACTION_VERIFIED"


def test_changed_policy_blocks_action_and_records_preflight(
    prepared_review, monkeypatch
):
    review_id = prepared_review()
    fake = FakeIam(document={"Statement": [{
        "Effect": "Allow", "Action": "*", "Resource": "*"
    }]})
    monkeypatch.setattr(remediation, "_get_iam_client", lambda: fake)
    result = remediation.remediate_access(None, None)
    assert result["failed"] == 1
    assert fake.actions == 0
    with db.get_connection() as conn:
        events = repo.remediation_history(conn, review_id)["action_events"]
        assert events[-1]["event_type"] == "PREFLIGHT_REJECTED"
        assert events[-1]["evidence"]["reason"] == "policy_document_changed"


def test_projection_only_approval_cannot_authorize_action(
    prepared_review, monkeypatch
):
    review_id = prepared_review()
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE remediation_approvals SET approval_id='legacy-row' WHERE review_id=?",
            (review_id,),
        )
        binding = repo.review_evidence_binding(conn, review_id)
        assert not repo.is_remediation_approved(conn, review_id, binding["snapshot_id"])
    monkeypatch.setattr(
        remediation, "_get_iam_client",
        lambda: pytest.fail("AWS must not be called for a projection-only approval"),
    )
    assert remediation.remediate_access(None, None)["skipped"] == 1


def test_lost_response_after_aws_action_reconciles_without_repeating(
    prepared_review, monkeypatch
):
    review_id = prepared_review()
    fake = FakeIam(crash=True)
    monkeypatch.setattr(remediation, "_get_iam_client", lambda: fake)
    assert remediation.remediate_access(None, None)["failed"] == 1
    with db.get_connection() as conn:
        assert repo.pending_remediation_intent(conn, review_id)
    assert remediation.remediate_access(None, None)["remediated"] == 1
    assert fake.actions == 1
    with db.get_connection() as conn:
        events = repo.remediation_history(conn, review_id)["action_events"]
        assert events[-1]["event_type"] == "ACTION_VERIFIED"
        assert events[-1]["evidence"]["recovered_after_uncertain_action"] is True
        assert repo.pending_remediation_intent(conn, review_id) is None


def test_unverified_postflight_holds_action_for_reconciliation(
    prepared_review, monkeypatch
):
    review_id = prepared_review()
    fake = FakeIam(remains=True)
    monkeypatch.setattr(remediation, "_get_iam_client", lambda: fake)
    assert remediation.remediate_access(None, None)["reconciliation_required"] == 1
    assert remediation.remediate_access(None, None)["reconciliation_required"] == 1
    assert fake.actions == 1
    with db.get_connection() as conn:
        assert repo.remediation_history(conn, review_id)["action_events"][-1][
            "event_type"
        ] == "RECONCILIATION_REQUIRED"
        assert conn.execute(
            "SELECT remediated_at FROM access_reviews WHERE review_id=?",
            (review_id,),
        ).fetchone() == (None,)


def test_live_action_requires_staging_acceptance_and_production_stays_closed(
    prepared_review, monkeypatch
):
    prepared_review()
    monkeypatch.setenv("APP_ENV", "development")
    assert remediation.remediate_access(None, None)["reason"] == (
        "staging_environment_required"
    )
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.delenv("STAGING_REMEDIATION_ACCEPTANCE_ID")
    assert remediation.remediate_access(None, None)["reason"] == (
        "staging_acceptance_required"
    )
    monkeypatch.setenv("APP_ENV", "production")
    assert remediation.remediate_access(None, None)["reason"] == (
        "production_live_remediation_disabled"
    )
    monkeypatch.setenv("DRY_RUN", "true")
    preview = remediation.remediate_access(None, None)
    assert preview["dry_run"] is True
    assert preview["total_pending"] == 1
    assert len(preview["preview"]) == 1
