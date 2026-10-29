# lambdas/risk_evaluation/handler.py
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from common import logger, repo
from common.db import db


def classify_risk(role_name: str) -> str:
    """Deterministic risk rules with word-boundary matching to avoid
    over-matching (e.g. 'rewrite' should not imply write access)."""
    import re

    name = (role_name or "").lower()

    def _has(*patterns: str) -> bool:
        return any(re.search(p, name) for p in patterns)

    # --- DETERMINISTIC RISK RULES (HIGH first) ---
    if _has(
        r"administratoraccess",
        r"\badmin(istrator)?\b",
        r"superuser",
        r"\broot\b",
        r"fullaccess",
        r"\bfull\b.*\baccess\b",
        r"poweruser.*full",
        r"iamfullaccess",
        r"\*",
    ):
        return "HIGH"
    if _has(
        r"poweruser",
        r"\bwrite\b",
        r"\bput\b",
        r"\bdelete\b",
        r"\bmodify\b",
        r"editaccess",
        r"developer",
        r"networkadmin",
        r"securityaudit.*write",
    ):
        return "MEDIUM"
    if _has(r"readonly", r"\bread\b", r"\bview\b", r"\baudit\b", r"billing.*read"):
        return "LOW"
    # Fail-closed for unknown privileged-looking names; otherwise LOW.
    if _has(r"admin", r"privileg", r"elevat", r"owner", r"super"):
        return "HIGH"
    return "LOW"
    # --------------------------------


def risk_reason(role_name: str) -> str:
    """Short human-readable reason for the deterministic classification."""
    import re

    name = (role_name or "").lower()
    if re.search(
        r"administratoraccess|\badmin(istrator)?\b|superuser|\broot\b|fullaccess|\bfull\b.*\baccess\b|poweruser.*full|iamfullaccess|\*",
        name,
    ):
        return "full/admin privilege pattern"
    if re.search(
        r"poweruser|\bwrite\b|\bput\b|\bdelete\b|\bmodify\b|editaccess|developer|networkadmin|securityaudit.*write",
        name,
    ):
        return "write/modify privilege pattern"
    if re.search(r"readonly|\bread\b|\bview\b|\baudit\b|billing.*read", name):
        return "read-only/audit pattern"
    if re.search(r"admin|privileg|elevat|owner|super", name):
        return "fail-closed privileged-looking name"
    return "no privileged pattern matched"


def evaluate_risk(event, context):
    logger.log("evaluate_risk", "start", "Starting Entitlement Risk Evaluation")

    with db.get_connection() as conn:
        roles = repo.list_roles(conn)

        updated_count = 0

        for role_id, role_name, current_risk, policy_document in roles:
            try:
                evidence = {"policy_name": role_name, "source": "name_heuristic"}
                if policy_document:
                    document = (
                        json.loads(policy_document)
                        if isinstance(policy_document, str)
                        else policy_document
                    )
                    statements = document.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    actions, resources, uncertain = [], [], False
                    grants = 0
                    for statement in statements:
                        if not isinstance(statement, dict):
                            uncertain = True
                            continue
                        effect = statement.get("Effect")
                        if effect not in ("Allow", "Deny"):
                            uncertain = True
                            continue
                        # NotAction and unusual AWS policy constructs need a real
                        # policy evaluator; treating them as a narrow allow is unsafe.
                        if effect == "Allow" and "NotAction" in statement:
                            uncertain = True
                        if effect != "Allow":
                            continue
                        grants += 1
                        action = statement.get("Action", [])
                        resource = statement.get("Resource", [])
                        actions.extend(action if isinstance(action, list) else [action])
                        resources.extend(
                            resource if isinstance(resource, list) else [resource]
                        )
                        if statement.get("Condition") or "NotResource" in statement:
                            uncertain = True
                    normalized = [str(a).lower() for a in actions]
                    wildcard = any(a == "*" or a.endswith(":*") for a in normalized)
                    write_verbs = (
                        "put",
                        "delete",
                        "create",
                        "update",
                        "modify",
                        "attach",
                        "detach",
                        "remove",
                        "terminate",
                        "stop",
                        "start",
                        "set",
                        "passrole",
                        "send",
                        "publish",
                    )
                    write = any(
                        any(x in a.split(":", 1)[-1] for x in write_verbs)
                        for a in normalized
                    )
                    broad_resource = any(
                        str(resource).strip() == "*" for resource in resources
                    )
                    if wildcard:
                        new_risk, reason = "HIGH", "policy grants wildcard actions"
                    elif uncertain:
                        new_risk, reason = (
                            "HIGH",
                            "policy constructs require manual evaluation",
                        )
                    elif not grants:
                        new_risk, reason = (
                            "HIGH",
                            "no analyzable allow grants; manual review required",
                        )
                    elif write:
                        new_risk, reason = "MEDIUM", "policy grants mutating actions"
                    elif broad_resource:
                        new_risk, reason = (
                            "MEDIUM",
                            "read actions apply to broad resources",
                        )
                    elif actions:
                        new_risk, reason = (
                            "LOW",
                            "policy contains explicit non-wildcard allow actions",
                        )
                    else:
                        new_risk, reason = (
                            "HIGH",
                            "no analyzable allow actions; manual review required",
                        )
                    evidence = {
                        "source": "policy_document",
                        "actions": actions[:200],
                        "resources": resources[:200],
                        "conditions_or_unsupported_constructs": uncertain,
                        "allow_statement_count": grants,
                    }
                else:
                    # Missing permission evidence must never be silently labelled low risk.
                    heuristic = classify_risk(role_name)
                    new_risk = "HIGH" if heuristic == "LOW" else heuristic
                    reason = "policy document unavailable; name heuristic only; manual review required"

                # Update only if risk level changed
                if new_risk != current_risk:
                    repo.update_role_risk(conn, role_id, new_risk)

                    updated_count += 1

                    if new_risk != "LOW":
                        logger.log(
                            "evaluate_risk",
                            "info",
                            f"{role_name} classified as {new_risk} ({reason})",
                            details={
                                "role_id": role_id,
                                "new_risk": new_risk,
                                "risk_reason": reason,
                            },
                        )

                repo.store_risk_assessment(
                    conn,
                    role_id,
                    new_risk,
                    reason,
                    evidence,
                    "policy-risk-v2",
                    datetime.now(timezone.utc).isoformat(),
                )

            except Exception as e:
                try:
                    repo.update_role_risk(conn, role_id, "HIGH")
                    repo.store_risk_assessment(
                        conn,
                        role_id,
                        "HIGH",
                        "policy analysis failed; manual review required",
                        {"source": "analysis_error", "error_type": type(e).__name__},
                        "policy-risk-v2",
                        datetime.now(timezone.utc).isoformat(),
                    )
                    updated_count += 1
                except Exception:
                    pass
                logger.log(
                    "evaluate_risk",
                    "error",
                    f"Error evaluating role {role_name}; classified high for manual review",
                    level="ERROR",
                    details={"role_id": role_id, "error_type": type(e).__name__},
                )
                continue

        logger.log(
            "evaluate_risk",
            "success",
            f"Risk Evaluation Complete. Updated {updated_count} entitlements.",
            details={"roles_updated": updated_count},
        )
        try:
            import uuid

            repo.insert_audit_log(
                conn,
                str(uuid.uuid4()),
                datetime.now(timezone.utc),
                "INFO",
                "evaluate_risk",
                "success",
                f"Risk Evaluation Complete. Updated {updated_count} entitlements.",
                details={"roles_updated": updated_count},
            )
        except Exception as e:
            logger.log(
                "evaluate_risk", "warn", f"audit log write failed: {e}", level="WARN"
            )
        return {"status": "success", "roles_updated": updated_count}


# --- LOCAL TESTING ---
if __name__ == "__main__":
    evaluate_risk(None, None)
