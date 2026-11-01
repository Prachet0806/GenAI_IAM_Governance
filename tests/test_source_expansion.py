"""Role and Identity Center paths, coverage gaps, and versioned risk rules."""

from datetime import datetime, timezone

import pytest

from common import evidence, repo
from common.db import db
from common.source_scanner import publish_source
from lambdas.generate_reviews.handler import generate_campaign
from lambdas.identity_discovery import handler as user_discovery
from lambdas.identity_center_discovery.handler import _assignments
from lambdas.risk_evaluation.handler import assess_policy, assess_trust_policy, evaluate_risk
from lambdas.role_discovery import handler as role_discovery
from lambdas.role_discovery.handler import role_principal
from scripts import migrate


ACCOUNT = "123456789012"
POLICY = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}


@pytest.fixture
def source_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'sources.db'}")
    migrate.apply_sqlite()


class _RoleIam:
    def get_paginator(self, operation):
        class Paginator:
            def paginate(self, **kwargs):
                if operation == "list_attached_role_policies":
                    return [{"AttachedPolicies": [{
                        "PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/Reader",
                        "PolicyName": "Reader",
                    }]}]
                if operation == "list_role_policies":
                    return [{"PolicyNames": ["InlineReader"]}]
                raise AssertionError(operation)
        return Paginator()

    def get_policy(self, **kwargs):
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, **kwargs):
        return {"PolicyVersion": {"Document": POLICY}}

    def get_role_policy(self, **kwargs):
        return {"PolicyDocument": POLICY}


def _role():
    return {
        "RoleId": "AROLE1", "RoleName": "audit-role",
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/audit-role",
        "CreateDate": datetime.now(timezone.utc),
        "AssumeRolePolicyDocument": {"Statement": [{
            "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }]},
    }


def test_role_paths_publish_and_campaign_freezes_three_grants(source_db):
    principal = role_principal(_RoleIam(), _role())
    assert {policy["GrantType"] for policy in principal["Policies"]} == {
        "ROLE_MANAGED", "ROLE_INLINE", "ROLE_TRUST",
    }
    published = publish_source(
        ACCOUNT, evidence.IAM_ROLE_POLICY_SCOPE, [principal],
        covered=["role_policies", "role_trust"],
        unassessed=["permission_boundaries", "effective_permissions"],
    )
    assert published["status"] == "COMPLETE"
    assert published["grants_seen"] == 3
    assert evaluate_risk(None, None)["grant_observations_assessed"] == 3
    campaign = generate_campaign({
        "account_id": ACCOUNT, "source_scope": evidence.IAM_ROLE_POLICY_SCOPE,
        "owner_sub": "owner",
    }, None)
    assert campaign["reviews_created"] == 3
    duplicate = generate_campaign({
        "account_id": ACCOUNT, "source_scope": evidence.IAM_ROLE_POLICY_SCOPE,
    }, None)
    assert duplicate["status"] == "blocked"
    assert duplicate["reason"] == "active_campaign_exists"
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM campaigns").fetchone() == (1,)
        assert conn.execute("SELECT principal_kind FROM users WHERE user_id='AROLE1'").fetchone() == ("IAM_ROLE",)
        assert conn.execute("SELECT account_id,source_scope,owner_sub,state FROM campaigns WHERE campaign_id=?", (campaign["campaign_id"],)).fetchone() == (
            ACCOUNT, evidence.IAM_ROLE_POLICY_SCOPE, "owner", "OPEN"
        )
        assert conn.execute("SELECT COUNT(*) FROM review_workflow_events WHERE campaign_id=?", (campaign["campaign_id"],)).fetchone() == (1,)
        assert all(row[0] for row in conn.execute("SELECT due_at FROM access_reviews WHERE campaign_id=?", (campaign["campaign_id"],)))


class _Admin:
    def list_permission_sets_provisioned_to_account(self, **kwargs):
        return {"PermissionSets": ["arn:aws:sso:::permissionSet/instance/ps-1"]}

    def describe_permission_set(self, **kwargs):
        return {"PermissionSet": {"Name": "ReaderSet"}}

    def get_inline_policy_for_permission_set(self, **kwargs):
        return {"InlinePolicy": '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'}

    def list_managed_policies_in_permission_set(self, **kwargs):
        return {"AttachedManagedPolicies": []}

    def list_customer_managed_policy_references_in_permission_set(self, **kwargs):
        return {"CustomerManagedPolicyReferences": [{"Name": "Unresolved"}]}

    def list_account_assignments(self, **kwargs):
        return {"AccountAssignments": [{"PrincipalType": "USER", "PrincipalId": "user-1"}]}


class _Store:
    def describe_user(self, **kwargs):
        return {"UserName": "named-user"}


def test_identity_center_missing_document_is_visible_and_high_risk(source_db):
    principals = _assignments(
        _Admin(), _Store(), object(), ACCOUNT,
        "arn:aws:sso:::instance/test", "d-test",
    )
    result = publish_source(
        ACCOUNT, evidence.IDENTITY_CENTER_SCOPE, principals,
        covered=["account_assignments"],
        unassessed=["group_membership", "effective_permissions"],
    )
    assert result["missing_policy_evidence"] == 1
    assert evaluate_risk(None, None)["grant_observations_assessed"] == 1
    with db.get_connection() as conn:
        row = conn.execute("SELECT evidence_status,missing_reason,policy_document FROM grant_observations").fetchone()
        assert row[:2] == ("MISSING", "customer_managed_policy_reference_unresolved")
        assert "s3:GetObject" in row[2]
        assert conn.execute("SELECT risk_level FROM grant_risk_assessments").fetchone() == ("HIGH",)
        coverage = repo.list_source_coverage(conn, ACCOUNT)
        assert coverage[0]["coverage"]["missing_policy_evidence"] == 1
        assert coverage[0]["eligible_for_campaign"] is True
    campaign = generate_campaign({
        "account_id": ACCOUNT, "source_scope": evidence.IDENTITY_CENTER_SCOPE,
    }, None)
    assert campaign["reviews_created"] == 1


def test_failed_new_source_attempt_preserves_old_snapshot_but_blocks_new_campaign(source_db):
    principal = role_principal(_RoleIam(), _role())
    first = publish_source(
        ACCOUNT, evidence.IAM_ROLE_POLICY_SCOPE, [principal],
        covered=["role_policies"], unassessed=[],
    )

    def broken():
        yield principal
        raise RuntimeError("pagination failed")

    second = publish_source(
        ACCOUNT, evidence.IAM_ROLE_POLICY_SCOPE, broken(),
        covered=["role_policies"], unassessed=[],
    )
    assert second["status"] == "FAILED"
    with db.get_connection() as conn:
        assert repo.published_snapshot(conn, ACCOUNT, evidence.IAM_ROLE_POLICY_SCOPE)[0] == first["snapshot_id"]
        assert repo.eligible_published_snapshot(conn, ACCOUNT, evidence.IAM_ROLE_POLICY_SCOPE) is None


def test_role_sts_failure_is_recorded_under_configured_source(source_db, monkeypatch):
    principal = role_principal(_RoleIam(), _role())
    first = publish_source(
        ACCOUNT, evidence.IAM_ROLE_POLICY_SCOPE, [principal], source="AWS",
        covered=["role_policies"], unassessed=[],
    )
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("AWS_ACCOUNT_ID", ACCOUNT)
    monkeypatch.setattr(role_discovery, "_source_account_id",
                        lambda: (_ for _ in ()).throw(RuntimeError("STS unavailable")))
    result = role_discovery.discover_roles(None, None)
    assert result["status"] == "FAILED"
    with db.get_connection() as conn:
        assert repo.published_snapshot(conn, ACCOUNT, evidence.IAM_ROLE_POLICY_SCOPE)[0] == first["snapshot_id"]
        assert repo.eligible_published_snapshot(conn, ACCOUNT, evidence.IAM_ROLE_POLICY_SCOPE) is None


def test_user_sts_failure_is_recorded_under_configured_source(source_db, monkeypatch):
    user = {
        "UserId": "U1", "UserName": "alice",
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice",
        "CreateDate": datetime.now(timezone.utc),
        "Policies": [{"PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/Reader",
                      "PolicyName": "Reader", "Document": POLICY}],
    }
    first = publish_source(
        ACCOUNT, evidence.IAM_USER_POLICY_SCOPE, [user], source="AWS",
        covered=["iam_users"], unassessed=[],
    )
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("AWS_ACCOUNT_ID", ACCOUNT)
    monkeypatch.setattr(user_discovery, "_source_account_id",
                        lambda: (_ for _ in ()).throw(RuntimeError("STS unavailable")))
    result = user_discovery.discover_identities(None, None)
    assert result["status"] == "failed"
    with db.get_connection() as conn:
        assert repo.published_snapshot(conn, ACCOUNT, evidence.IAM_USER_POLICY_SCOPE)[0] == first["snapshot_id"]
        assert repo.eligible_published_snapshot(conn, ACCOUNT, evidence.IAM_USER_POLICY_SCOPE) is None


@pytest.mark.parametrize("document,expected", [
    ({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}, "HIGH"),
    ({"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}, "HIGH"),
    ({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]}, "HIGH"),
    (POLICY, "MEDIUM"),
    ({"Statement": [{"Effect": "Allow", "Action": "s3:*Object",
                     "Resource": "arn:aws:s3:::private/*"}]}, "HIGH"),
    (None, "HIGH"),
])
def test_versioned_policy_risk_corpus(document, expected):
    assert assess_policy("example", document)[0] == expected


def test_role_trust_risk_corpus():
    assert assess_trust_policy({"Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole",
    }]}, ACCOUNT)[0] == "HIGH"
    assert assess_trust_policy({"Statement": [{
        "Effect": "Allow", "Principal": {"AWS": "210987654321"}, "Action": "sts:AssumeRole",
    }]}, ACCOUNT)[0] == "HIGH"
    assert assess_trust_policy(_role()["AssumeRolePolicyDocument"], ACCOUNT)[0] == "MEDIUM"
