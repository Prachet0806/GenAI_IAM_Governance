#lambdas/identity_discovery/handler.py
import boto3
import json
import uuid
from datetime import datetime, timezone
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, logger
from common.db import db
from common import repo


def _is_mock() -> bool:
    return config.is_mock_iam()

def _mock_identities():
    """Rich 12-user seed data for offline demos (covers HIGH/MEDIUM/LOW + edge cases)."""
    now = datetime.now(timezone.utc)
    aws = "arn:aws:iam::123456789012"
    managed = lambda name: {"PolicyArn": f"{aws}:policy/{name}", "PolicyName": name,
                            "Document": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*" if "Administrator" in name else "iam:List*", "Resource": "*"}]}}
    return [
        {"UserId": "MOCK-USER-01", "UserName": "alice@example.com", "Arn": f"{aws}:user/alice",
         "CreateDate": now, "Policies": [managed("PowerUserAccess"), managed("ReadOnlyAccess")]},
        {"UserId": "MOCK-USER-02", "UserName": "bob@example.com", "Arn": f"{aws}:user/bob",
         "CreateDate": now, "Policies": [managed("AdministratorAccess")]},
        {"UserId": "MOCK-USER-03", "UserName": "carol@example.com", "Arn": f"{aws}:user/carol",
         "CreateDate": now, "Policies": [managed("SuperUserFull")]},
        {"UserId": "MOCK-USER-04", "UserName": "dave@example.com", "Arn": f"{aws}:user/dave",
         "CreateDate": now, "Policies": [managed("BreakGlass-AdministratorAccess")]},
        {"UserId": "MOCK-USER-05", "UserName": "erin@example.com", "Arn": f"{aws}:user/erin",
         "CreateDate": now, "Policies": [managed("DeveloperAccess")]},
        {"UserId": "MOCK-USER-06", "UserName": "frank@example.com", "Arn": f"{aws}:user/frank",
         "CreateDate": now, "Policies": [managed("NetworkAdmin")]},
        {"UserId": "MOCK-USER-07", "UserName": "grace@example.com", "Arn": f"{aws}:user/grace",
         "CreateDate": now, "Policies": [managed("Put-Delete-Modify-Data")]},
        {"UserId": "MOCK-USER-08", "UserName": "heidi@example.com", "Arn": f"{aws}:user/heidi",
         "CreateDate": now, "Policies": [managed("ReadOnlyAccess")]},
        {"UserId": "MOCK-USER-09", "UserName": "ivan@example.com", "Arn": f"{aws}:user/ivan",
         "CreateDate": now, "Policies": [managed("BillingReadOnly")]},
        {"UserId": "MOCK-USER-10", "UserName": "judy@example.com", "Arn": f"{aws}:user/judy",
         "CreateDate": now, "Policies": [managed("SecurityAuditView")]},
        # Edge cases: 'rewrite-engine' must NOT trigger write->MEDIUM; oscar exercises multi-entitlement.
        {"UserId": "MOCK-USER-11", "UserName": "mallory@example.com", "Arn": f"{aws}:user/mallory",
         "CreateDate": now, "Policies": [managed("rewrite-engine")]},
        {"UserId": "MOCK-USER-12", "UserName": "oscar@example.com", "Arn": f"{aws}:user/oscar",
         "CreateDate": now, "Policies": [managed("ReadOnlyAccess"), managed("PowerUserAccess")]},
    ]

def _iam_client():
    from botocore.config import Config as BotoConfig
    kwargs = {"region_name": config.get_aws_region()}
    client_config = BotoConfig(connect_timeout=5, read_timeout=20,
                               retries={"mode": "standard", "max_attempts": 5})
    profile = config.get_aws_profile()
    if profile:
        session = boto3.Session(profile_name=profile, region_name=kwargs["region_name"])
        return session.client("iam", config=client_config)
    return boto3.client("iam", region_name=kwargs["region_name"], config=client_config)

def _list_all_attached_policies(iam_client, principal_name: str, principal_type: str = "user"):
    """Paginate attached-policy APIs for users or groups."""
    policies = []
    marker = None
    operation = "list_attached_user_policies" if principal_type == "user" else "list_attached_group_policies"
    parameter = "UserName" if principal_type == "user" else "GroupName"
    while True:
        kwargs = {parameter: principal_name}
        if marker:
            kwargs["Marker"] = marker
        resp = getattr(iam_client, operation)(**kwargs)
        policies.extend(resp.get("AttachedPolicies", []))
        if resp.get("IsTruncated"):
            next_marker = resp.get("Marker")
            if not next_marker or next_marker == marker:
                raise RuntimeError("IAM policy pagination did not advance")
            marker = next_marker
        else:
            break
    return policies


def _list_all(iam_client, operation: str, result_key: str, **kwargs):
    """Paginate IAM list operations without silently truncating inventory."""
    paginator = iam_client.get_paginator(operation)
    return [item for page in paginator.paginate(**kwargs) for item in page.get(result_key, [])]


def _inline_policy(iam_client, operation: str, getter: str, principal: str):
    names = _list_all(iam_client, operation, "PolicyNames", **{principal: getter})
    items = []
    for name in names:
        # IAM exposes separate get_user_policy/get_group_policy operations.
        policy_getter = "get_user_policy" if principal == "UserName" else "get_group_policy"
        document = getattr(iam_client, policy_getter)(**{principal: getter, "PolicyName": name}).get("PolicyDocument")
        if isinstance(document, str):
            from urllib.parse import unquote
            document = json.loads(unquote(document))
        if not isinstance(document, dict):
            raise RuntimeError("Inline IAM policy document is missing or invalid")
        items.append({"PolicyArn": f"inline:{principal.lower()}:{getter}:{name}",
                      "PolicyName": f"{getter}:{name}", "Document": document})
    return items


def _user_entitlements(iam_client, user):
    """Return direct policies plus policies inherited through IAM groups."""
    user_name = user["UserName"]
    policies = []
    for policy in _list_all_attached_policies(iam_client, user_name):
        policy["Document"] = _get_policy_document(iam_client, policy["PolicyArn"])
        policies.append(policy)
    policies.extend(_inline_policy(iam_client, "list_user_policies", "UserName", user_name))
    for group in _list_all(iam_client, "list_groups_for_user", "Groups", UserName=user_name):
        group_name = group["GroupName"]
        for policy in _list_all_attached_policies(iam_client, group_name, "group"):
            policy["Document"] = _get_policy_document(iam_client, policy["PolicyArn"])
            policies.append(policy)
        policies.extend(_inline_policy(iam_client, "list_group_policies", "GroupName", group_name))
    # Deduplicate the same group policy inherited through multiple enumeration paths.
    unique = {p["PolicyArn"]: p for p in policies}
    return list(unique.values())


def _get_policy_document(iam_client, policy_arn: str):
    policy = iam_client.get_policy(PolicyArn=policy_arn).get("Policy", {})
    version_id = policy.get("DefaultVersionId")
    if not version_id:
        raise RuntimeError("Managed policy has no readable default version")
    version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id).get("PolicyVersion", {})
    document = version.get("Document")
    if isinstance(document, str):
        from urllib.parse import unquote
        document = json.loads(unquote(document))
    if not isinstance(document, dict):
        raise RuntimeError("Managed policy document is missing or invalid")
    return document

def _iter_identities():
    if _is_mock():
        for entry in _mock_identities():
            yield entry
    else:
        iam_client = _iam_client()
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                policies = _user_entitlements(iam_client, user)
                yield {**user, "Policies": policies}

def discover_identities(event, context):
    logger.log("discover_identities", "start", "Starting Identity Discovery")
    run_id = str(uuid.uuid4())
    started = datetime.now(timezone.utc).isoformat()
    mode = "MOCK" if _is_mock() else "AWS"
    scope = "iam-users-direct-and-group-managed-and-inline-policies-v2"
    with db.get_connection() as conn:
        repo.lock_inventory_remediation(conn)
        repo.start_discovery_run(conn, run_id, started, f"{mode}:{scope}")
    user_count, errors = 0, 0
    pairs = set()
    try:
        with db.get_connection() as conn:
            # Hold the shared database lock through reconciliation and commit so
            # a remediation cannot detach against a snapshot being published.
            repo.lock_inventory_remediation(conn)
            for user in _iter_identities():
                try:
                    u_id = user['UserId']
                    u_name = user['UserName']
                    u_arn = user['Arn']
                    created_at = user['CreateDate'].isoformat()
                    repo.insert_user(conn, u_id, u_name, u_arn, created_at)
                    for poly in user.get("Policies", []):
                        p_arn, p_name = poly['PolicyArn'], poly['PolicyName']
                        repo.insert_role(conn, p_arn, p_name, "LOW")
                        repo.update_role_policy(conn, p_arn, poly.get("Document"), datetime.now(timezone.utc).isoformat())
                        repo.link_user_role(conn, u_id, p_arn)
                        pairs.add((u_id, p_arn))
                    user_count += 1
                except Exception as e:
                    errors += 1
                    logger.log("discover_identities", "error", "Failed processing discovered user", level="ERROR",
                               details={"user_name": user.get("UserName", "UNKNOWN"), "error_type": type(e).__name__})
            if errors:
                raise RuntimeError("Incomplete identity data; current entitlement snapshot was not replaced")
            repo.reconcile_user_roles(conn, pairs)
            status = "COMPLETE"
            repo.finish_discovery_run(conn, run_id, datetime.now(timezone.utc).isoformat(), status, user_count, errors,
                                      {"scope_version": scope, "complete_for_declared_scope": True,
                                       "coverage": ["iam_users", "user_attached_managed_policies",
                                                   "user_inline_policies", "group_membership",
                                                   "group_attached_managed_policies", "group_inline_policies"]})
    except Exception as e:
        with db.get_connection() as conn:
            repo.finish_discovery_run(conn, run_id, datetime.now(timezone.utc).isoformat(), "FAILED", user_count, errors + 1,
                                      {"error_type": type(e).__name__})
        logger.log("discover_identities", "error", "Discovery failed; previous entitlement links retained",
                   level="ERROR", details={"run_id": run_id, "error_type": type(e).__name__})
        return {"status": "failed", "run_id": run_id, "users_processed": user_count}

    logger.log("discover_identities", "success" if errors == 0 else "warn",
               f"Discovery {status.lower()} ({mode})", details={"run_id": run_id, "users_processed": user_count, "errors": errors})
    try:
        with db.get_connection() as conn:
            repo.insert_audit_log(conn, str(uuid.uuid4()), datetime.now(timezone.utc), "INFO", "discover_identities", status,
                                  "Identity discovery run completed", entity_type="discovery_run", entity_id=run_id,
                                  details={"users_processed": user_count, "errors": errors})
    except Exception as exc:
        logger.log("discover_identities", "warn", "Audit event persistence failed", level="WARN", details={"error_type": type(exc).__name__})
    return {"status": status.lower(), "run_id": run_id, "users_processed": user_count, "errors": errors}


# --- LOCAL TESTING ---
if __name__ == "__main__":
    discover_identities(None, None)
