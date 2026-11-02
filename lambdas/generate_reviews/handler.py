# lambdas/generate_reviews/handler.py
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import evidence, logger, repo, workflow
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
        expected_snapshot = (event or {}).get("snapshot_id") if isinstance(event, dict) else None
        allowed_scopes = {
            evidence.IAM_USER_POLICY_SCOPE, evidence.IAM_ROLE_POLICY_SCOPE,
            evidence.IDENTITY_CENTER_SCOPE,
        }
        if requested_scope and requested_scope not in allowed_scopes:
            return {"status": "blocked", "reason": "unsupported_source_scope"}
        source_scope = requested_scope or evidence.IAM_USER_POLICY_SCOPE
        snapshot = repo.eligible_published_snapshot(
            conn, requested_account, source_scope
        )
        if not snapshot:
            return {"status": "blocked", "reason": "no_eligible_published_snapshot"}
        snapshot_id = snapshot["snapshot_id"]
        if expected_snapshot and expected_snapshot != snapshot_id:
            return {"status": "blocked", "reason": "snapshot_changed",
                    "snapshot_id": snapshot_id}
        if not repo.snapshot_risk_complete(
            conn, snapshot_id, evidence.POLICY_RULE_VERSION
        ):
            return {"status": "blocked", "reason": "snapshot_risk_incomplete",
                    "snapshot_id": snapshot_id}
        if existing := repo.active_campaign_for_snapshot(conn, snapshot_id):
            return {"status": "blocked", "reason": "active_campaign_exists",
                    "snapshot_id": snapshot_id, "campaign_id": existing}
        entitlements = repo.list_assessed_grants(
            conn, snapshot_id, evidence.POLICY_RULE_VERSION
        )
        if not entitlements:
            return {"status": "blocked", "reason": "no_reviewable_grants",
                    "snapshot_id": snapshot_id}
        campaign_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        requested_name = (event or {}).get("name") if isinstance(event, dict) else None
        campaign_name = requested_name.strip() if isinstance(requested_name, str) and requested_name.strip() else f"Access Campaign {now.strftime('%Y-%m-%d %H:%M:%S %Z')}"
        owner_sub = (event or {}).get("owner_sub", "system") if isinstance(event, dict) else "system"
        if not isinstance(owner_sub, str) or not owner_sub.strip():
            return {"status": "blocked", "reason": "invalid_campaign_owner"}
        requested_due = (event or {}).get("due_at") if isinstance(event, dict) else None
        try:
            due = datetime.fromisoformat(requested_due) if requested_due else now + timedelta(days=30)
            if due.tzinfo is None or due.utcoffset() is None or due <= now:
                raise ValueError("Campaign deadline must be future and timezone-aware")
        except (TypeError, ValueError):
            return {"status": "blocked", "reason": "invalid_campaign_deadline"}
        due_at = due.astimezone(timezone.utc).isoformat()
        created_count = 0

        repo.create_pinned_campaign(
            conn, campaign_id, campaign_name, now.isoformat(), snapshot_id,
            owner_sub.strip(), due_at,
        )
        workflow.record_event(
            conn, campaign_id, "CAMPAIGN_CREATED", owner_sub.strip(),
            new="OPEN", details={"snapshot_id": snapshot_id, "due_at": due_at},
        )

        for user_id, role_id, grant_id, observation_id, assessment_id, _risk in entitlements:
            review_id = str(uuid.uuid4())
            created_at = datetime.now(timezone.utc).isoformat()
            if repo.create_pinned_review(
                conn, review_id, campaign_id, user_id, role_id,
                snapshot_id, grant_id, observation_id, assessment_id, created_at,
            ):
                created_count += 1
            else:
                # The connection manager rolls back the campaign and all
                # earlier reviews; a partial certification is never published.
                raise RuntimeError("Pending grant conflict during campaign creation")

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
