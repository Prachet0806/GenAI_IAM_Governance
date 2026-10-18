#lambdas/remediation/handler.py
import boto3
from datetime import datetime, timedelta, timezone
import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, logger, repo
from common.db import db


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def _should_detach(role_name: str, role_arn: str = "", allowlist: set | None = None, denylist: set | None = None):
    """Exact/bounded matching: denylist blocks exact names or explicit substrings
    only when wrapped; allowlist (if non-empty) requires exact match on name or ARN."""
    allow = {_norm(a) for a in (allowlist if allowlist is not None else config.get_allowlist())}
    # Mandatory protections cannot be bypassed by custom configuration or a
    # caller-supplied denylist used in tests/tools.
    deny = {_norm(d) for d in config.MANDATORY_DENYLIST}
    deny.update(_norm(d) for d in (denylist if denylist is not None else config.get_denylist()))
    name = _norm(role_name)
    arn = _norm(role_arn)
    # Deny: exact match on name/arn, or substring only if the denylist entry
    # explicitly opts into substring with * wildcards (e.g. *break-glass*).
    for entry in deny:
        if not entry:
            continue
        if entry.startswith("*") and entry.endswith("*") and len(entry) > 2:
            needle = entry.strip("*")
            if needle and (needle in name or needle in arn):
                return False, f"Denied by denylist pattern ({entry})"
        elif name == entry or arn == entry:
            return False, f"Denied by denylist ({entry})"
    if allow and not (name in allow or arn in allow):
        return False, "Skipped: not in remediation allowlist"
    return True, "Allowed"


def _get_iam_client():
    from botocore.config import Config as BotoConfig
    kwargs = {"region_name": config.get_aws_region()}
    client_config = BotoConfig(connect_timeout=5, read_timeout=20,
                               retries={"mode": "standard", "max_attempts": 3})
    profile = config.get_aws_profile()
    if profile:
        import boto3 as _boto3
        session = _boto3.Session(profile_name=profile, region_name=kwargs["region_name"])
        return session.client("iam", config=client_config)
    return boto3.client("iam", region_name=kwargs["region_name"], config=client_config)


def _is_policy_attached(iam, user_name: str, policy_arn: str) -> bool:
    paginator = iam.get_paginator("list_attached_user_policies")
    return any(policy.get("PolicyArn") == policy_arn
               for page in paginator.paginate(UserName=user_name)
               for policy in page.get("AttachedPolicies", []))


def _is_group_policy(iam, user_name: str, policy_arn: str) -> bool:
    """Group-derived access is never remediated by detaching a user policy."""
    groups = iam.get_paginator("list_groups_for_user")
    for page in groups.paginate(UserName=user_name):
        for group in page.get("Groups", []):
            policies = iam.get_paginator("list_attached_group_policies")
            if any(p.get("PolicyArn") == policy_arn
                   for policy_page in policies.paginate(GroupName=group["GroupName"])
                   for p in policy_page.get("AttachedPolicies", [])):
                return True
    return False


def remediate_access(event, context):
    dry_run = config.is_dry_run()
    enabled = config.is_remediation_enabled()
    allowlist = config.get_allowlist()
    live_authorized = config.is_live_remediation_explicitly_allowed()
    production = os.getenv("APP_ENV", "development").lower() == "production"
    if not dry_run and enabled and production:
        logger.log("remediate_access", "error",
                   "Live remediation is disabled in production until an authenticated approval service is integrated",
                   level="ERROR")
        return {"status": "blocked", "reason": "production_approval_integration_missing", "remediated": 0, "skipped": 0, "dry_run": dry_run}
    if not dry_run and enabled and config.is_mock_iam():
        logger.log("remediate_access", "error", "Live remediation is forbidden while MOCK_IAM is enabled", level="ERROR")
        return {"status": "blocked", "reason": "mock_mode", "remediated": 0, "skipped": 0, "dry_run": dry_run}
    if not dry_run and enabled and (not live_authorized or not allowlist):
        logger.log("remediate_access", "error",
                   "Live remediation blocked: explicit ALLOW_LIVE_REMEDIATION and a non-empty allowlist are required",
                   level="ERROR")
        return {"status": "blocked", "reason": "missing_live_safety_configuration", "remediated": 0, "skipped": 0, "dry_run": dry_run}
    logger.log(
        "remediate_access",
        "start",
        "Starting Access Remediation Engine",
        details={"DRY_RUN": dry_run, "ENABLE_REMEDIATION": enabled},
    )
    if dry_run or not enabled:
        logger.log(
            "remediate_access",
            "info",
            "Detachments will NOT be executed unless DRY_RUN is false AND ENABLE_REMEDIATION is true.",
        )

    with db.get_connection() as conn:
        discovery_run_id = None
        if not dry_run and enabled:
            latest = repo.latest_discovery_run(conn)
            if (not latest or latest[2] != "COMPLETE" or not latest[1]
                    or not str(latest[3] or "").startswith("AWS:iam-users-direct-and-group-managed-and-inline-policies-v2")):
                logger.log("remediate_access", "error", "Live remediation blocked: no latest complete inventory scan",
                           level="ERROR")
                return {"status": "blocked", "reason": "inventory_not_complete", "remediated": 0, "skipped": 0, "dry_run": dry_run}
            discovery_run_id = latest[0]
            observed = latest[1]
            if not isinstance(observed, datetime):
                observed = datetime.fromisoformat(str(observed).replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - observed.astimezone(timezone.utc)).total_seconds() / 3600
            if age_hours < -0.1 or age_hours > config.get_max_discovery_age_hours():
                logger.log("remediate_access", "error", "Live remediation blocked: inventory scan is stale or has an invalid timestamp",
                           level="ERROR", details={"age_hours": round(age_hours, 2),
                                                    "max_age_hours": config.get_max_discovery_age_hours()})
                return {"status": "blocked", "reason": "inventory_stale", "remediated": 0, "skipped": 0, "dry_run": dry_run}
        revocations = repo.list_revocations(conn)

        if dry_run or not enabled:
            preview = [
                {"review_id": r_id, "role": r}
                for r_id, _u, r, _arn in revocations[:10]
            ]
            logger.log(
                "remediate_access",
                "plan",
                "Preflight only; no detachments will be executed.",
                details={"total_pending": len(revocations), "preview": preview},
            )

        action_count = 0
        skipped_count = 0
        iam = None

        for review_id, user_name, role_name, role_arn in revocations:
            claim_token = None
            logger.log(
                "remediate_access",
                "processing",
                "Processing revocation",
                entity_type="access_review",
                entity_id=review_id,
                details={"role_name": role_name},
            )

            try:
                allowed, reason = _should_detach(role_name, role_arn, allowlist=allowlist)
                if not allowed:
                    logger.log(
                        "remediate_access",
                        "skip",
                        reason,
                        entity_type="access_review",
                        entity_id=review_id,
                    )
                    skipped_count += 1
                elif dry_run or not enabled:
                    logger.log(
                        "remediate_access",
                        "dry_run",
                        f"Would detach {role_name}",
                        entity_type="access_review",
                        entity_id=review_id,
                    )
                    skipped_count += 1
                elif not repo.is_remediation_approved(conn, review_id, discovery_run_id):
                    logger.log("remediate_access", "skip",
                               "Independent authenticated remediation approval is required",
                               entity_type="access_review", entity_id=review_id)
                    skipped_count += 1
                else:
                    claim_token = str(uuid.uuid4())
                    claimed_at = datetime.now(timezone.utc)
                    lease_until = claimed_at + timedelta(minutes=5)
                    if not repo.claim_remediation(conn, review_id, claim_token,
                                                  claimed_at.isoformat(), lease_until.isoformat()):
                        logger.log("remediate_access", "skip", "Another worker holds the remediation lease",
                                   entity_type="access_review", entity_id=review_id)
                        skipped_count += 1
                        continue
                    # Make the lease visible before calling AWS so another worker
                    # cannot pass the same eligibility check concurrently.
                    conn.commit()
                    current_discovery = repo.latest_discovery_run(conn)
                    if (not current_discovery or current_discovery[0] != discovery_run_id
                            or current_discovery[2] != "COMPLETE"
                            or not repo.is_current_entitlement(conn, review_id)
                            or not repo.is_remediation_approved(conn, review_id, discovery_run_id)):
                        repo.release_remediation_claim(conn, review_id, claim_token)
                        logger.log("remediate_access", "skip", "Review, approval, entitlement, or discovery snapshot changed",
                                   entity_type="access_review", entity_id=review_id)
                        skipped_count += 1
                        continue
                    # This worker only knows how to detach a direct managed user
                    # policy. Inline and group-derived grants need distinct workflows.
                    if not role_arn.startswith("arn:aws:iam::"):
                        repo.release_remediation_claim(conn, review_id, claim_token)
                        logger.log("remediate_access", "skip", "Entitlement is not a detachable managed-policy ARN",
                                   entity_type="access_review", entity_id=review_id)
                        skipped_count += 1
                        continue
                    if iam is None:
                        iam = _get_iam_client()
                    if _is_group_policy(iam, user_name, role_arn):
                        repo.release_remediation_claim(conn, review_id, claim_token)
                        logger.log("remediate_access", "skip", "Policy is also inherited through an IAM group",
                                   entity_type="access_review", entity_id=review_id)
                        skipped_count += 1
                        continue
                    if not _is_policy_attached(iam, user_name, role_arn):
                        repo.mark_remediated(conn, review_id, datetime.now(timezone.utc).isoformat())
                        repo.release_remediation_claim(conn, review_id, claim_token)
                        logger.log("remediate_access", "success", "Revoked entitlement was already absent in AWS",
                                   entity_type="access_review", entity_id=review_id)
                        action_count += 1
                        continue
                    iam.detach_user_policy(UserName=user_name, PolicyArn=role_arn)
                    logger.log(
                        "remediate_access",
                        "success",
                        "AWS policy detached.",
                        entity_type="access_review",
                        entity_id=review_id,
                    )
                    # Only mark remediated after a verified detach — never on
                    # skip or dry-run, otherwise future runs hide the row forever.
                    repo.mark_remediated(conn, review_id, datetime.now(timezone.utc).isoformat())
                    repo.release_remediation_claim(conn, review_id, claim_token)
                    action_count += 1

            except Exception as e:
                if claim_token:
                    try:
                        repo.release_remediation_claim(conn, review_id, claim_token)
                    except Exception:
                        pass
                logger.log(
                    "remediate_access",
                    "error",
                    f"Remediation failed ({type(e).__name__})",
                    level="ERROR",
                    entity_type="access_review",
                    entity_id=review_id,
                    details={"error_type": type(e).__name__},
                )
                continue

        logger.log(
            "remediate_access",
            "complete",
            f"Remediation Complete. Detached {action_count}, skipped {skipped_count}.",
            details={"remediated": action_count, "skipped": skipped_count, "dry_run": dry_run},
        )
        try:
            import uuid
            repo.insert_audit_log(
                conn, str(uuid.uuid4()), datetime.now(timezone.utc), "INFO",
                "remediate_access", "complete",
                f"Remediation Complete. Detached {action_count}, skipped {skipped_count}.",
                details={"remediated": action_count, "skipped": skipped_count, "dry_run": dry_run},
            )
        except Exception as e:
            logger.log("remediate_access", "warn", f"audit log write failed: {e}", level="WARN")
        return {
            "status": "success",
            "remediated": action_count,
            "skipped": skipped_count,
            "dry_run": dry_run,
        }


# --- LOCAL TESTING ---
if __name__ == "__main__":
    try:
        remediate_access(None, None)
    except Exception as exc:  # pragma: no cover
        logger.log("remediate_access", "error", str(exc), level="ERROR")
