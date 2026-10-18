#lambdas/generate_reviews/handler.py
import uuid
from datetime import datetime, timezone
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, logger, repo
from common.db import db

def generate_campaign(event, context):
    logger.log("generate_campaign", "start", "Starting Access Certification Campaign Generation")

    with db.get_connection() as conn:
        campaign_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        campaign_name = f"Access Campaign {now.strftime('%Y-%m-%d %H:%M:%S %Z')}"
        created_count = 0

        repo.create_campaign(conn, campaign_id, campaign_name, now.isoformat())

        entitlements = repo.list_entitlements(conn)

        for user_id, role_id, risk_level in entitlements:
            review_id = str(uuid.uuid4())
            created_at = datetime.now(timezone.utc).isoformat()
            if repo.create_review_if_pending(conn, review_id, campaign_id, user_id, role_id, created_at):
                created_count += 1

        logger.log(
            "generate_campaign",
            "success",
            f"Campaign created with {created_count} review tasks.",
            details={"campaign_id": campaign_id, "reviews_created": created_count},
        )
        try:
            repo.insert_audit_log(
                conn, str(uuid.uuid4()), datetime.now(timezone.utc), "INFO",
                "generate_campaign", "success",
                f"Campaign created with {created_count} review tasks.",
                entity_type="campaign", entity_id=campaign_id,
                details={"campaign_id": campaign_id, "reviews_created": created_count},
            )
        except Exception as e:
            logger.log("generate_campaign", "warn", f"audit log write failed: {e}", level="WARN")
        return {
            "status": "success",
            "campaign_id": campaign_id,
            "reviews_created": created_count
        }

# --- LOCAL TESTING ---
if __name__ == "__main__":
    generate_campaign(None, None)
