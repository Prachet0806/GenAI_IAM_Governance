#lambdas/remediation/handler.py
import boto3
from datetime import datetime, timezone
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, logger, repo
from common.db import db

# ⚠️ SAFETY SWITCHES
DRY_RUN = config.DRY_RUN
ENABLE_REMEDIATION = config.ENABLE_REMEDIATION
ALLOWLIST = config.ALLOWLIST
DENYLIST = config.DENYLIST


def _should_detach(role_name: str):
    role_lower = role_name.lower()
    if any(deny in role_lower for deny in DENYLIST):
        return False, f"Denied by denylist ({','.join(DENYLIST)})"
    if ALLOWLIST and not any(allow in role_lower for allow in ALLOWLIST):
        return False, "Skipped: not in remediation allowlist"
    return True, "Allowed"


def _get_iam_client():
    return boto3.client("iam")


def remediate_access(event, context):
    logger.log(
        "remediate_access",
        "start",
        "Starting Access Remediation Engine",
        details={"DRY_RUN": DRY_RUN, "ENABLE_REMEDIATION": ENABLE_REMEDIATION},
    )
    if DRY_RUN or not ENABLE_REMEDIATION:
        logger.log(
            "remediate_access",
            "info",
            "Detachments will NOT be executed unless DRY_RUN is false AND ENABLE_REMEDIATION is true.",
        )

    with db.get_connection() as conn:
        revocations = repo.list_revocations(conn)

        if DRY_RUN or not ENABLE_REMEDIATION:
            preview = [
                {"review_id": r_id, "user": u, "role": r, "arn": arn}
                for r_id, u, r, arn in revocations[:10]
            ]
            logger.log(
                "remediate_access",
                "plan",
                "Preflight only; no detachments will be executed.",
                details={"total_pending": len(revocations), "preview": preview},
            )

        action_count = 0
        iam = None

        for review_id, user_name, role_name, role_arn in revocations:
            logger.log(
                "remediate_access",
                "processing",
                f"Processing revocation: {user_name} -> {role_name}",
                entity_type="access_review",
                entity_id=review_id,
                details={"user_name": user_name, "role_name": role_name},
            )

            try:
                allowed, reason = _should_detach(role_name)
                if not allowed:
                    logger.log(
                        "remediate_access",
                        "skip",
                        reason,
                        entity_type="access_review",
                        entity_id=review_id,
                    )
                elif DRY_RUN or not ENABLE_REMEDIATION:
                    logger.log(
                        "remediate_access",
                        "dry_run",
                        f"Would detach {role_name} from {user_name}",
                        entity_type="access_review",
                        entity_id=review_id,
                    )
                else:
                    if iam is None:
                        iam = _get_iam_client()
                    iam.detach_user_policy(UserName=user_name, PolicyArn=role_arn)
                    logger.log(
                        "remediate_access",
                        "success",
                        "AWS policy detached.",
                        entity_type="access_review",
                        entity_id=review_id,
                    )

                # Mark remediation as completed
                repo.mark_remediated(conn, review_id, datetime.now(timezone.utc).isoformat())

                action_count += 1

            except Exception as e:
                logger.log(
                    "remediate_access",
                    "error",
                    f"Remediation failed for {user_name}: {e}",
                    level="ERROR",
                    entity_type="access_review",
                    entity_id=review_id,
                )
                continue

        logger.log(
            "remediate_access",
            "complete",
            f"Remediation Complete. Processed {action_count} access revocations.",
            details={"remediated": action_count, "dry_run": DRY_RUN},
        )
        return {
            "status": "success",
            "remediated": action_count,
            "dry_run": DRY_RUN,
        }


# --- LOCAL TESTING ---
if __name__ == "__main__":
    try:
        remediate_access(None, None)
    except Exception as exc:  # pragma: no cover
        logger.log("remediate_access", "error", str(exc), level="ERROR")
