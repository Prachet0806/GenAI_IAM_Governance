"""Opt-in SDK-to-Floci scan. Run against a disposable local Floci instance."""

import json
import os
import uuid

import pytest

from common import aws_clients, evidence
from common.db import db
from lambdas.identity_discovery.handler import discover_identities
from lambdas.role_discovery.handler import discover_roles
from scripts import migrate


@pytest.mark.skipif(os.getenv("FLOCI_INTEGRATION") != "1", reason="requires Floci")
def test_floci_iam_scan_publishes_real_sdk_observation(tmp_path, monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.setenv("AWS_ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("FLOCI_ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'floci.db'}")
    aws_clients.assert_floci_ready()
    assert aws_clients.client("sts").get_caller_identity()["Account"] == "111111111111"

    iam = aws_clients.client("iam")
    suffix = uuid.uuid4().hex[:10]
    user_name = f"governance-floci-{suffix}"
    policy_name = f"governance-floci-reader-{suffix}"
    policy_document = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
    }]})
    iam.create_user(UserName=user_name)
    policy_arn = iam.create_policy(
        PolicyName=policy_name, PolicyDocument=policy_document,
    )["Policy"]["Arn"]
    iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    role_name = f"governance-floci-role-{suffix}"
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }))

    migrate.apply_sqlite()
    result = discover_identities(None, None)
    assert result["status"] == "complete", result
    role_result = discover_roles(None, None)
    assert role_result["status"] == "COMPLETE", role_result
    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT source, account_id, source_scope FROM discovery_runs "
            "WHERE run_id=?", (result["run_id"],)
        ).fetchone()
        assert row == (
            f"FLOCI:{evidence.IAM_USER_POLICY_SCOPE}",
            "111111111111", evidence.IAM_USER_POLICY_SCOPE,
        )
        grant = conn.execute(
            "SELECT p.attachment_id, o.evidence_status FROM grant_observations o "
            "JOIN grant_paths p ON p.grant_id=o.grant_id "
            "WHERE p.attachment_id=?", (policy_arn,),
        ).fetchone()
        assert grant == (policy_arn, "COMPLETE")
        role = conn.execute(
            "SELECT p.principal_arn FROM grant_paths p "
            "JOIN grant_observations o ON o.grant_id=p.grant_id "
            "WHERE o.snapshot_id=? AND p.grant_type='ROLE_TRUST' AND p.principal_arn LIKE ?",
            (role_result["snapshot_id"], f"%:role/{role_name}"),
        ).fetchone()
        assert role is not None
