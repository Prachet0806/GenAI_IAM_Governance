# lambdas/risk_evaluation/handler.py
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from common import evidence, logger, repo
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


def assess_policy(policy_name: str, document: dict | None):
    """Assess one policy document; this is not principal effective access."""
    if not isinstance(document, dict):
        return (
            "HIGH",
            "policy document unavailable; manual review required",
            {"source": "missing_policy_document", "policy_name": policy_name},
        )
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        statements = []
    actions, resources, uncertain = [], [], False
    grants = 0
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in ("Allow", "Deny"):
            uncertain = True
            continue
        if statement["Effect"] != "Allow":
            continue
        grants += 1
        if "NotAction" in statement:
            uncertain = True
        action = statement.get("Action", [])
        resource = statement.get("Resource", [])
        actions.extend(action if isinstance(action, list) else [action])
        resources.extend(resource if isinstance(resource, list) else [resource])
        if statement.get("Condition") or "NotResource" in statement:
            uncertain = True
    normalized = [str(action).lower() for action in actions]
    wildcard = any(action == "*" or action.endswith(":*") for action in normalized)
    write_verbs = (
        "put", "delete", "create", "update", "modify", "attach", "detach",
        "remove", "terminate", "stop", "start", "set", "passrole", "send", "publish",
    )
    write = any(
        any(verb in action.split(":", 1)[-1] for verb in write_verbs)
        for action in normalized
    )
    broad_resource = any(str(resource).strip() == "*" for resource in resources)
    if wildcard:
        risk, reason = "HIGH", "policy grants wildcard actions"
    elif uncertain:
        risk, reason = "HIGH", "policy constructs require manual evaluation"
    elif not grants:
        risk, reason = "HIGH", "no analyzable allow grants; manual review required"
    elif write:
        risk, reason = "MEDIUM", "policy grants mutating actions"
    elif broad_resource:
        risk, reason = "MEDIUM", "read actions apply to broad resources"
    elif actions:
        risk, reason = "LOW", "policy contains explicit non-wildcard allow actions"
    else:
        risk, reason = "HIGH", "no analyzable allow actions; manual review required"
    return risk, reason, {
        "source": "policy_document",
        "actions": actions[:200],
        "resources": resources[:200],
        "conditions_or_unsupported_constructs": uncertain,
        "allow_statement_count": grants,
    }


def evaluate_risk(event, context):
    logger.log("evaluate_risk", "start", "Starting snapshot policy risk evaluation")
    with db.get_connection() as conn:
        observations = repo.list_current_observations(conn)
        if not observations:
            return {"status": "blocked", "reason": "no_published_snapshot", "roles_updated": 0}
        assessed = 0
        for observation in observations:
            observation_id, snapshot_id, grant_id, policy_id, policy_name, document_json = observation[:6]
            try:
                risk, reason, risk_evidence = assess_policy(
                    policy_name, json.loads(document_json)
                )
            except (TypeError, ValueError, KeyError) as exc:
                risk, reason = "HIGH", "policy analysis failed; manual review required"
                risk_evidence = {"source": "analysis_error", "error_type": type(exc).__name__}
            assessed_at = datetime.now(timezone.utc).isoformat()
            repo.store_snapshot_risk(
                conn, observation, risk, reason, risk_evidence,
                evidence.POLICY_RULE_VERSION, assessed_at,
            )
            # Mutable role/risk rows remain compatibility projections. Reviews
            # reference the append-only assessment for their grant observation.
            repo.update_role_risk(conn, policy_id, risk)
            repo.store_risk_assessment(
                conn, policy_id, risk, reason, risk_evidence,
                evidence.POLICY_RULE_VERSION, assessed_at,
            )
            assessed += 1
        repo.insert_audit_log(
            conn, str(uuid.uuid4()), datetime.now(timezone.utc),
            "INFO", "evaluate_risk", "success",
            f"Assessed {assessed} grant observations",
            details={"grant_observations": assessed},
        )
    logger.log(
        "evaluate_risk", "success", f"Assessed {assessed} grant observations",
        details={"grant_observations": assessed},
    )
    return {"status": "success", "grant_observations_assessed": assessed,
            "roles_updated": assessed}


# --- LOCAL TESTING ---
if __name__ == "__main__":
    evaluate_risk(None, None)
