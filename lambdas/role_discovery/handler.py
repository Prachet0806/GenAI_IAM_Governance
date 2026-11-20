"""IAM role policy and trust observations, scoped separately from IAM users."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, evidence
from common.source_scanner import publish_source
from lambdas.identity_discovery.handler import (
    _get_policy_document, _iam_client, _is_mock, _list_all, _source_account_id,
)


def _document(value):
    if isinstance(value, str):
        value = json.loads(unquote(value))
    if not isinstance(value, dict):
        raise ValueError("IAM role policy document is missing or invalid")
    return value


def role_principal(iam_client, role: dict):
    role_id = role["RoleId"]
    role_name = role["RoleName"]
    role_arn = role["Arn"]
    policies = []
    trust = _document(role.get("AssumeRolePolicyDocument"))
    policies.append({
        "PolicyArn": f"trust:{role_arn}",
        "PolicyName": f"{role_name}:trust",
        "Document": trust,
        "GrantType": "ROLE_TRUST",
        "SourceId": role_id,
        "SourceName": role_name,
        "AttachmentId": "trust",
    })
    for policy in _list_all(
        iam_client, "list_attached_role_policies", "AttachedPolicies",
        RoleName=role_name,
    ):
        document, version = _get_policy_document(iam_client, policy["PolicyArn"])
        policies.append({
            **policy, "Document": document, "PolicyVersion": version,
            "GrantType": "ROLE_MANAGED", "SourceId": role_id,
            "SourceName": role_name, "AttachmentId": policy["PolicyArn"],
        })
    for name in _list_all(
        iam_client, "list_role_policies", "PolicyNames", RoleName=role_name,
    ):
        response = iam_client.get_role_policy(RoleName=role_name, PolicyName=name)
        policies.append({
            "PolicyArn": f"inline:role:{role_id}:{name}",
            "PolicyName": f"{role_name}:{name}",
            "Document": _document(response.get("PolicyDocument")),
            "GrantType": "ROLE_INLINE", "SourceId": role_id,
            "SourceName": role_name, "AttachmentId": name,
        })
    return {
        "UserId": role_id, "UserName": role_name, "Arn": role_arn,
        "CreateDate": role.get("CreateDate") or datetime.now(timezone.utc),
        "PrincipalKind": "IAM_ROLE", "Policies": policies,
    }


def _iter_roles(account_id: str):
    if _is_mock():
        account = _source_account_id()
        yield {
            "UserId": "MOCK-ROLE-1", "UserName": "sample-auditor-role",
            "Arn": f"arn:aws:iam::{account}:role/sample-auditor-role",
            "CreateDate": datetime.now(timezone.utc), "PrincipalKind": "IAM_ROLE",
            "Policies": [{
                "PolicyArn": f"trust:arn:aws:iam::{account}:role/sample-auditor-role",
                "PolicyName": "sample-auditor-role:trust",
                "Document": {"Statement": [{"Effect": "Allow", "Principal": {
                    "Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                "GrantType": "ROLE_TRUST", "SourceId": "MOCK-ROLE-1",
                "SourceName": "sample-auditor-role", "AttachmentId": "trust",
            }],
        }
        return
    if _source_account_id() != account_id:
        raise RuntimeError("AWS credentials do not match AWS_ACCOUNT_ID")
    client = _iam_client()
    for role in _list_all(client, "list_roles", "Roles"):
        yield role_principal(client, role)


def discover_roles(event, context):
    account_id = _source_account_id() if _is_mock() else config.get_aws_account_id()
    return publish_source(
        account_id, evidence.IAM_ROLE_POLICY_SCOPE, _iter_roles(account_id),
        source="MOCK" if _is_mock() else "AWS",
        covered=["iam_roles", "role_attached_managed_policies", "role_inline_policies", "role_trust_policies"],
        unassessed=["role_permission_boundaries", "service_control_policies", "resource_policies", "effective_permissions"],
    )


if __name__ == "__main__":
    print(discover_roles(None, None))
