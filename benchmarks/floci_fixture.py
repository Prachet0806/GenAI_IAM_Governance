"""Deterministic IAM user-policy fixture and independent expected-grant model."""

import json
import random
from pathlib import Path

from botocore.exceptions import ClientError

from common import aws_clients, config, evidence

PROFILE_DIR = Path(__file__).resolve().parents[1] / "tests/fixtures/floci/profiles"


def _policy_document(index: int) -> dict:
    actions = [
        "s3:GetObject", "s3:PutObject", "iam:*", "ec2:DescribeInstances",
        "s3:DeleteObject", "s3:ListBucket",
    ]
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": actions[index % len(actions)], "Resource": "*",
    }]}


def make_manifest(profile: str = "baseline", seed: int = 42) -> dict:
    if not profile.isalnum() or seed < 0:
        raise ValueError("Invalid benchmark profile or seed")
    spec = json.loads((PROFILE_DIR / f"{profile}.json").read_text(encoding="utf-8"))
    if not (0 <= spec["active_users"] <= spec["users"] and spec["groups"] > 1
            and spec["managed_policies"] == 6):
        raise ValueError("Unsupported benchmark profile")
    account_id = config.get_source_account_id()
    namespace = f"bench-{profile}-{seed}"
    rng = random.Random(seed)
    policies = {
        f"{namespace}-p-{i:02d}": _policy_document(i)
        for i in range(spec["managed_policies"])
    }
    policy_names = list(policies)
    groups = {
        f"{namespace}-g-{i:02d}": {
            "managed": [policy_names[i % len(policy_names)]],
            "inline": {"inline-g": _policy_document((i + 1) % 6)},
        }
        for i in range(spec["groups"])
    }
    group_names = list(groups)
    users = {}
    expected = []
    for i in range(spec["users"]):
        name = f"{namespace}-u-{i:04d}"
        active = i < spec["active_users"]
        managed = [policy_names[rng.randrange(len(policy_names))]] if active else []
        if active and i % 10 == 0:
            extra = policy_names.index(managed[0])
            managed.append(policy_names[(extra + 1) % len(policy_names)])
        inline = {"inline-u": _policy_document(i % 6)} if active and i % 4 == 0 else {}
        memberships = [group_names[i % len(group_names)]] if active else []
        if active and i % 5 == 0:
            memberships.append(group_names[(i + 1) % len(group_names)])
        users[name] = {"managed": managed, "inline": inline, "groups": memberships}
        expected.extend((name, "DIRECT_MANAGED", name, p) for p in managed)
        expected.extend((name, "DIRECT_INLINE", name, f"{name}:{p}") for p in inline)
        for group in memberships:
            expected.extend((name, "GROUP_MANAGED", group, p) for p in groups[group]["managed"])
            expected.extend((name, "GROUP_INLINE", group, f"{group}:{p}") for p in groups[group]["inline"])
    counts = {
        "users": len(users), "groups": len(groups), "roles": 0,
        "managed_policies": len(policies),
        "inline_policies": sum(len(u["inline"]) for u in users.values())
        + sum(len(g["inline"]) for g in groups.values()),
        "memberships": sum(len(u["groups"]) for u in users.values()),
        "attachments": sum(len(u["managed"]) for u in users.values())
        + sum(len(g["managed"]) for g in groups.values()),
        "grant_paths": len(expected), "observations": len(expected),
    }
    return {
        "schema_version": "floci-benchmark-v1", "profile": profile, "seed": seed,
        "namespace": namespace, "account_id": account_id,
        "source_scope": evidence.IAM_USER_POLICY_SCOPE,
        "managed_policies": policies, "groups": groups, "users": users,
        "expected_grants": [list(row) for row in sorted(expected)], "counts": counts,
    }


def _listed(client, operation: str, key: str, **kwargs) -> list:
    return [item for page in client.get_paginator(operation).paginate(**kwargs)
            for item in page.get(key, [])]


def _missing(exc: ClientError) -> bool:
    return exc.response["Error"]["Code"] in {"NoSuchEntity", "NoSuchEntityException"}


def _ensure(client, get_operation: str, create_operation: str, get_args: dict, create_args: dict) -> bool:
    try:
        getattr(client, get_operation)(**get_args)
        return False
    except ClientError as exc:
        if not _missing(exc):
            raise
    getattr(client, create_operation)(**create_args)
    return True


def seed_floci(manifest: dict) -> dict:
    if config.iam_source_mode() != "FLOCI":
        raise RuntimeError("The benchmark seeder requires Floci mode")
    aws_clients.assert_floci_ready()
    if manifest["account_id"] != config.get_source_account_id():
        raise ValueError("Manifest account does not match Floci account")
    iam = aws_clients.client("iam")
    ns = manifest["namespace"]
    # Whole-source scans would collect unrelated users, so require a dedicated emulator.
    existing_users = _listed(iam, "list_users", "Users")
    existing_groups = _listed(iam, "list_groups", "Groups")
    existing_roles = _listed(iam, "list_roles", "Roles")
    if (any(u["UserName"] not in manifest["users"] for u in existing_users)
            or any(g["GroupName"] not in manifest["groups"] for g in existing_groups)
            or existing_roles):
        raise RuntimeError("Floci contains unrelated IAM principals; use a disposable instance")
    writes = 0
    for name, document in manifest["managed_policies"].items():
        arn = f"arn:aws:iam::{manifest['account_id']}:policy/{name}"
        if _ensure(iam, "get_policy", "create_policy", {"PolicyArn": arn},
                   {"PolicyName": name, "PolicyDocument": json.dumps(document)}):
            writes += 1
        current = iam.get_policy(PolicyArn=arn)["Policy"]
        actual = iam.get_policy_version(
            PolicyArn=arn, VersionId=current["DefaultVersionId"]
        )["PolicyVersion"]["Document"]
        if isinstance(actual, str):
            from urllib.parse import unquote
            actual = json.loads(unquote(actual))
        if actual != document:
            raise RuntimeError(f"Existing managed policy differs: {name}")
    for name, group in manifest["groups"].items():
        writes += _ensure(iam, "get_group", "create_group", {"GroupName": name}, {"GroupName": name})
        attached = {p["PolicyName"] for p in _listed(
            iam, "list_attached_group_policies", "AttachedPolicies", GroupName=name
        )}
        for policy in group["managed"]:
            if policy not in attached:
                iam.attach_group_policy(
                    GroupName=name,
                    PolicyArn=f"arn:aws:iam::{manifest['account_id']}:policy/{policy}",
                )
                writes += 1
        for inline, document in group["inline"].items():
            iam.put_group_policy(GroupName=name, PolicyName=inline,
                                 PolicyDocument=json.dumps(document))
            writes += 1
    for name, user in manifest["users"].items():
        writes += _ensure(iam, "get_user", "create_user", {"UserName": name}, {"UserName": name})
        attached = {p["PolicyName"] for p in _listed(
            iam, "list_attached_user_policies", "AttachedPolicies", UserName=name
        )}
        for policy in user["managed"]:
            if policy not in attached:
                iam.attach_user_policy(
                    UserName=name,
                    PolicyArn=f"arn:aws:iam::{manifest['account_id']}:policy/{policy}",
                )
                writes += 1
        for inline, document in user["inline"].items():
            iam.put_user_policy(UserName=name, PolicyName=inline,
                                PolicyDocument=json.dumps(document))
            writes += 1
        current_groups = {g["GroupName"] for g in _listed(
            iam, "list_groups_for_user", "Groups", UserName=name
        )}
        for group in user["groups"]:
            if group not in current_groups:
                iam.add_user_to_group(GroupName=group, UserName=name)
                writes += 1
    return {"writes": writes, "namespace": ns}


def verify_floci(manifest: dict) -> dict:
    iam = aws_clients.client("iam")

    def document(value):
        if isinstance(value, str):
            from urllib.parse import unquote
            return json.loads(unquote(value))
        return value

    users = {u["UserName"] for u in _listed(iam, "list_users", "Users")}
    groups = {g["GroupName"] for g in _listed(iam, "list_groups", "Groups")}
    roles = {r["RoleName"] for r in _listed(iam, "list_roles", "Roles")}
    if users != set(manifest["users"]) or groups != set(manifest["groups"]) or roles:
        raise AssertionError("Floci principal inventory differs from manifest")
    for name, user in manifest["users"].items():
        attached = {p["PolicyName"] for p in _listed(
            iam, "list_attached_user_policies", "AttachedPolicies", UserName=name
        )}
        inline = set(_listed(iam, "list_user_policies", "PolicyNames", UserName=name))
        memberships = {g["GroupName"] for g in _listed(
            iam, "list_groups_for_user", "Groups", UserName=name
        )}
        if (attached != set(user["managed"]) or inline != set(user["inline"])
                or memberships != set(user["groups"])):
            raise AssertionError(f"Floci user differs from manifest: {name}")
        for policy, expected in user["inline"].items():
            actual = iam.get_user_policy(UserName=name, PolicyName=policy)["PolicyDocument"]
            if document(actual) != expected:
                raise AssertionError(f"Floci user inline policy differs: {name}/{policy}")
    for name, group in manifest["groups"].items():
        attached = {p["PolicyName"] for p in _listed(
            iam, "list_attached_group_policies", "AttachedPolicies", GroupName=name
        )}
        inline = set(_listed(iam, "list_group_policies", "PolicyNames", GroupName=name))
        if attached != set(group["managed"]) or inline != set(group["inline"]):
            raise AssertionError(f"Floci group differs from manifest: {name}")
        for policy, expected in group["inline"].items():
            actual = iam.get_group_policy(GroupName=name, PolicyName=policy)["PolicyDocument"]
            if document(actual) != expected:
                raise AssertionError(f"Floci group inline policy differs: {name}/{policy}")
    policies = {p["PolicyName"] for p in _listed(
        iam, "list_policies", "Policies", Scope="Local"
    )}
    if policies != set(manifest["managed_policies"]):
        raise AssertionError("Floci managed policies differ from manifest")
    for name, expected in manifest["managed_policies"].items():
        arn = f"arn:aws:iam::{manifest['account_id']}:policy/{name}"
        version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
        actual = iam.get_policy_version(
            PolicyArn=arn, VersionId=version
        )["PolicyVersion"]["Document"]
        if document(actual) != expected:
            raise AssertionError(f"Floci managed policy differs: {name}")
    return manifest["counts"]
