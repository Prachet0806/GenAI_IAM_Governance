"""Stable identities and canonical values for IAM grant-path evidence."""

import hashlib
import json
import re
from datetime import datetime, timezone

IAM_USER_POLICY_SCOPE = "iam-users-direct-and-group-managed-and-inline-policies-v2"
POLICY_RULE_VERSION = "policy-risk-v2"


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_id(*parts: str) -> str:
    return hashlib.sha256(canonical_json(parts).encode("utf-8")).hexdigest()


def account_from_arn(arn: str) -> str:
    match = re.match(r"^arn:[^:]+:iam::(\d{12}):", arn or "")
    if not match:
        raise ValueError("IAM principal ARN does not contain an AWS account ID")
    return match.group(1)


def grant_observation(account_id: str, user: dict, policy: dict, snapshot_id: str):
    """Produce a path identity and observation without using policy content as a key."""
    principal_id = user["UserId"]
    principal_arn = user["Arn"]
    if account_from_arn(principal_arn) != account_id:
        raise ValueError("Discovered principal belongs to a different AWS account")
    grant_type = policy.get("GrantType", "DIRECT_MANAGED")
    if grant_type not in {
        "DIRECT_MANAGED",
        "DIRECT_INLINE",
        "GROUP_MANAGED",
        "GROUP_INLINE",
    }:
        raise ValueError("Unsupported IAM grant type")
    source_id = policy.get("SourceId") or principal_id
    source_name = policy.get("SourceName") or user["UserName"]
    attachment_id = policy.get("AttachmentId") or policy.get("PolicyArn")
    if not attachment_id or (grant_type.startswith("GROUP_") and source_id == principal_id):
        raise ValueError("Grant path is missing its source attachment identity")
    document = policy.get("Document")
    if not isinstance(document, dict):
        raise ValueError("Grant path has no readable policy document")
    policy_id = (
        policy["PolicyArn"]
        if grant_type.endswith("MANAGED")
        else f"inline:{account_id}:{grant_type}:{source_id}:{attachment_id}"
    )
    grant_id = stable_id(account_id, principal_id, grant_type, source_id, attachment_id)
    document_json = canonical_json(document)
    return {
        "grant_id": grant_id,
        "observation_id": stable_id(snapshot_id, grant_id),
        "snapshot_id": snapshot_id,
        "account_id": account_id,
        "principal_id": principal_id,
        "principal_arn": principal_arn,
        "principal_name": user["UserName"],
        "grant_type": grant_type,
        "source_id": source_id,
        "source_name": source_name,
        "attachment_id": attachment_id,
        "policy_id": policy_id,
        "policy_name": policy["PolicyName"],
        "policy_version": policy.get("PolicyVersion"),
        "policy_sha256": hashlib.sha256(document_json.encode("utf-8")).hexdigest(),
        "policy_document": document_json,
        "observed_at": policy.get("ObservedAt")
        or datetime.now(timezone.utc).isoformat(),
    }
