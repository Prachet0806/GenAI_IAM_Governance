#lambdas/generate_reviews/handler.py
import uuid
from datetime import datetime
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
        campaign_name = f"Access Campaign {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
        created_count = 0

        repo.create_campaign(conn, campaign_id, campaign_name, datetime.utcnow().isoformat())

        entitlements = repo.list_entitlements(conn)

        for user_id, role_id, risk_level in entitlements:
            # Deduplicate: skip if a pending review already exists
            if repo.pending_review_exists(conn, user_id, role_id):
                continue

            review_id = str(uuid.uuid4())
            created_at = datetime.utcnow().isoformat()

            repo.create_review(conn, review_id, campaign_id, user_id, role_id, created_at)

            created_count += 1

        logger.log(
            "generate_campaign",
            "success",
            f"Campaign created with {created_count} review tasks.",
            details={"campaign_id": campaign_id, "reviews_created": created_count},
        )
        return {
            "status": "success",
            "campaign_id": campaign_id,
            "reviews_created": created_count
        }

# --- LOCAL TESTING ---
if __name__ == "__main__":
    generate_campaign(None, None)
