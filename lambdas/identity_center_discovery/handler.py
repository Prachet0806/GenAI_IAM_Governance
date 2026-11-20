"""Identity Center account assignment paths with explicit policy gaps."""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, evidence
from common.source_scanner import publish_source
from lambdas.identity_discovery.handler import _get_policy_document


def _clients():
    session = boto3.Session(
        profile_name=config.get_aws_profile() or None,
        region_name=config.get_aws_region(),
    )
    return session.client("sso-admin"), session.client("identitystore"), session.client("iam")


def _pages(client, operation: str, key: str, **arguments):
    token = None
    seen = set()
    while True:
        params = dict(arguments)
        if token:
            params["NextToken"] = token
        page = getattr(client, operation)(**params)
        for item in page.get(key, []):
            yield item
        next_token = page.get("NextToken")
        if not next_token:
            return
        if next_token in seen:
            raise RuntimeError("Identity Center pagination did not advance")
        seen.add(next_token)
        token = next_token


def _instance(admin, requested_arn: str | None):
    instances = list(_pages(admin, "list_instances", "Instances"))
    matches = [item for item in instances if not requested_arn or item["InstanceArn"] == requested_arn]
    if len(matches) != 1:
        raise ValueError("Select exactly one accessible Identity Center instance")
    return matches[0]["InstanceArn"], matches[0]["IdentityStoreId"]


def _permission_set_policy(admin, iam, instance_arn: str, permission_set_arn: str):
    permission_set = admin.describe_permission_set(
        InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
    )["PermissionSet"]
    statements = []
    missing = []
    inline = admin.get_inline_policy_for_permission_set(
        InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
    ).get("InlinePolicy")
    if inline:
        parsed = json.loads(inline)
        if not isinstance(parsed, dict):
            raise ValueError("Identity Center inline policy is invalid")
        items = parsed.get("Statement", [])
        statements.extend(items if isinstance(items, list) else [items])
    for attached in _pages(
        admin, "list_managed_policies_in_permission_set", "AttachedManagedPolicies",
        InstanceArn=instance_arn, PermissionSetArn=permission_set_arn,
    ):
        try:
            document, _version = _get_policy_document(iam, attached["Arn"])
            items = document.get("Statement", [])
            statements.extend(items if isinstance(items, list) else [items])
        except Exception:
            missing.append("managed_policy_document_unavailable")
    customer_refs = list(_pages(
        admin, "list_customer_managed_policy_references_in_permission_set",
        "CustomerManagedPolicyReferences",
        InstanceArn=instance_arn, PermissionSetArn=permission_set_arn,
    ))
    if customer_refs:
        missing.append("customer_managed_policy_reference_unresolved")
    return {
        "PolicyArn": permission_set_arn,
        "PolicyName": permission_set["Name"],
        "Document": {"Version": "2012-10-17", "Statement": statements},
        "EvidenceStatus": "MISSING" if missing else "COMPLETE",
        "MissingReason": ",".join(sorted(set(missing))) if missing else None,
    }


def _principal(store, identity_store_id: str, instance_arn: str, assignment: dict):
    kind = assignment["PrincipalType"]
    principal_id = assignment["PrincipalId"]
    if kind == "USER":
        response = store.describe_user(IdentityStoreId=identity_store_id, UserId=principal_id)
        name = response.get("UserName") or response.get("DisplayName")
        principal_kind = "IDENTITY_CENTER_USER"
    elif kind == "GROUP":
        response = store.describe_group(IdentityStoreId=identity_store_id, GroupId=principal_id)
        name = response.get("DisplayName")
        principal_kind = "IDENTITY_CENTER_GROUP"
    else:
        raise ValueError("Unknown Identity Center assignment principal type")
    if not name:
        raise ValueError("Identity Center principal name is unavailable")
    stable_principal_id = evidence.stable_id(instance_arn, kind, principal_id)
    return {
        "UserId": stable_principal_id,
        "UserName": name,
        "Arn": f"identity-center://{instance_arn}/{kind.lower()}/{principal_id}",
        "CreateDate": datetime.now(timezone.utc),
        "PrincipalKind": principal_kind,
    }


def _assignments(admin, store, iam, account_id: str, instance_arn: str, identity_store_id: str):
    principals = {}
    for permission_set_arn in _pages(
        admin, "list_permission_sets_provisioned_to_account", "PermissionSets",
        InstanceArn=instance_arn, AccountId=account_id,
    ):
        policy = _permission_set_policy(admin, iam, instance_arn, permission_set_arn)
        for assignment in _pages(
            admin, "list_account_assignments", "AccountAssignments",
            InstanceArn=instance_arn, AccountId=account_id,
            PermissionSetArn=permission_set_arn,
        ):
            principal = _principal(store, identity_store_id, instance_arn, assignment)
            principal_id = principal["UserId"]
            observed = principals.setdefault(principal_id, principal)
            observed.setdefault("Policies", []).append({
                **policy,
                "GrantType": "IDENTITY_CENTER_ASSIGNMENT",
                "SourceId": permission_set_arn,
                "SourceName": policy["PolicyName"],
                "AttachmentId": f"{account_id}:{assignment['PrincipalType']}:{assignment['PrincipalId']}",
            })
    yield from principals.values()


def discover_identity_center(event, context):
    event = event if isinstance(event, dict) else {}
    account_id = str(event.get("account_id", ""))
    if not re.fullmatch(r"\d{12}", account_id):
        return {"status": "blocked", "reason": "account_id_required"}
    def principals():
        admin, store, iam = _clients()
        instance_arn, identity_store_id = _instance(admin, event.get("instance_arn"))
        yield from _assignments(
            admin, store, iam, account_id, instance_arn, identity_store_id
        )

    return publish_source(
        account_id, evidence.IDENTITY_CENTER_SCOPE,
        principals(),
        covered=["account_assignments", "permission_sets", "inline_policy",
                 "aws_managed_policy_documents", "identity_store_principal_names"],
        unassessed=["identity_center_group_membership", "permission_boundaries",
                    "customer_managed_policy_documents", "effective_permissions"],
    )


if __name__ == "__main__":
    print(discover_identity_center({}, None))
