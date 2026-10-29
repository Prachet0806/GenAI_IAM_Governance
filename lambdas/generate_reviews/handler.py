# lambdas/generate_reviews/handler.py
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import evidence, logger, repo
from common.db import db


def generate_campaign(event, context):
    logger.log(
        "generate_campaign",
        "start",
        "Starting Access Certification Campaign Generation",
    )

    with db.get_connection() as conn:
        repo.lock_inventory_remediation(conn)
        requested_account = (event or {}).get("account_id") if isinstance(event, dict) else None
        requested_scope = (event or {}).get("source_scope") if isinstance(event, dict) else None
        if requested_scope and requested_scope != evidence.IAM_USER_POLICY_SCOPE:
            return {"status": "blocked", "reason": "unsupported_source_scope"}
        snapshot = repo.eligible_published_snapshot(
            conn, requested_account, evidence.IAM_USER_POLICY_SCOPE
        )
        if not snapshot:
            return {"status": "blocked", "reason": "no_eligible_published_snapshot"}
        snapshot_id = snapshot["snapshot_id"]
        if not repo.snapshot_risk_complete(
            conn, snapshot_id, evidence.POLICY_RULE_VERSION
        ):
            return {"status": "blocked", "reason": "snapshot_risk_incomplete",
                    "snapshot_id": snapshot_id}
        campaign_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        campaign_name = f"Access Campaign {now.strftime('%Y-%m-%d %H:%M:%S %Z')}"
        created_count = 0

        repo.create_pinned_campaign(
            conn, campaign_id, campaign_name, now.isoformat(), snapshot_id
        )

        entitlements = repo.list_assessed_grants(
            conn, snapshot_id, evidence.POLICY_RULE_VERSION
        )

        for user_id, role_id, grant_id, observation_id, assessment_id, _risk in entitlements:
            review_id = str(uuid.uuid4())
            created_at = datetime.now(timezone.utc).isoformat()
            if repo.create_pinned_review(
                conn, review_id, campaign_id, user_id, role_id,
                snapshot_id, grant_id, observation_id, assessment_id, created_at,
            ):
                created_count += 1

        logger.log(
            "generate_campaign",
            "success",
            f"Campaign created with {created_count} review tasks.",
            details={"campaign_id": campaign_id, "snapshot_id": snapshot_id,
                     "review_scope": "GRANT_PATH", "reviews_created": created_count},
        )
        try:
            repo.insert_audit_log(
                conn,
                str(uuid.uuid4()),
                datetime.now(timezone.utc),
                "INFO",
                "generate_campaign",
                "success",
                f"Campaign created with {created_count} review tasks.",
                entity_type="campaign",
                entity_id=campaign_id,
                details={"campaign_id": campaign_id, "snapshot_id": snapshot_id,
                         "review_scope": "GRANT_PATH", "reviews_created": created_count},
            )
        except Exception as e:
            logger.log(
                "generate_campaign",
                "warn",
                f"audit log write failed: {e}",
                level="WARN",
            )
        return {
            "status": "success",
            "campaign_id": campaign_id,
            "snapshot_id": snapshot_id,
            "review_scope": "GRANT_PATH",
            "reviews_created": created_count,
        }


# --- LOCAL TESTING ---
if __name__ == "__main__":
    generate_campaign(None, None)
