#lambdas/risk_evaluation/handler.py
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from common import config, logger, repo
from common.db import db

def evaluate_risk(event, context):
    logger.log("evaluate_risk", "start", "Starting Entitlement Risk Evaluation")

    with db.get_connection() as conn:
        roles = repo.list_roles(conn)

        updated_count = 0

        for role_id, role_name, current_risk in roles:
            try:
                name = role_name.lower()
                new_risk = "LOW"

                # --- DETERMINISTIC RISK RULES ---
                if "administratoraccess" in name or "fullaccess" in name:
                    new_risk = "HIGH"
                elif "poweruser" in name or "write" in name:
                    new_risk = "MEDIUM"
                elif "readonly" in name:
                    new_risk = "LOW"
                # --------------------------------

                # Update only if risk level changed
                if new_risk != current_risk:
                    repo.update_role_risk(conn, role_id, new_risk)

                    updated_count += 1

                    if new_risk != "LOW":
                        logger.log(
                            "evaluate_risk",
                            "info",
                            f"{role_name} classified as {new_risk}",
                            details={"role_id": role_id, "new_risk": new_risk},
                        )

            except Exception as e:
                logger.log(
                    "evaluate_risk",
                    "error",
                    f"Error evaluating role {role_name}: {e}",
                    level="ERROR",
                    details={"role_id": role_id},
                )
                continue

        logger.log(
            "evaluate_risk",
            "success",
            f"Risk Evaluation Complete. Updated {updated_count} entitlements.",
            details={"roles_updated": updated_count},
        )
        return {
            "status": "success",
            "roles_updated": updated_count
        }

# --- LOCAL TESTING ---
if __name__ == "__main__":
    evaluate_risk(None, None)
