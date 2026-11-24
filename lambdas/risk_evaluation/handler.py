# lambdas/risk_evaluation/handler.py
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from common import evidence, logger, policy_assessment, repo
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
    sensitive_actions = {
        "sts:assumerole", "secretsmanager:getsecretvalue", "kms:decrypt",
        "ssm:getparameter", "ssm:getparameters", "ssm:getparametersbypath",
    }
    privileged = any(
        action in sensitive_actions
        or (action.startswith("iam:") and not action.split(":", 1)[1].startswith(
            ("get", "list", "simulate", "generatecredentialreport")
        ))
        for action in normalized
    )
    # IAM accepts wildcards anywhere in an action name. A partial wildcard
    # cannot safely be called read-only without expanding the service catalog.
    wildcard = any("*" in action or "?" in action for action in normalized)
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
        risk, reason = "HIGH", "policy grants or may grant wildcard actions"
    elif uncertain:
        risk, reason = "HIGH", "policy constructs require manual evaluation"
    elif privileged:
        risk, reason = "HIGH", "policy grants sensitive access or IAM privilege changes"
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


def assess_trust_policy(document: dict | None, account_id: str):
    """Assess who may assume a role; this is not effective permission evaluation."""
    if not isinstance(document, dict):
        return "HIGH", "role trust policy unavailable", {"source": "missing_trust_policy"}
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        return "HIGH", "role trust policy cannot be analyzed", {"source": "trust_policy"}
    principals = []
    uncertain = False
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
            uncertain = True
            continue
        if statement["Effect"] == "Deny":
            continue
        if "NotPrincipal" in statement or "NotAction" in statement or statement.get("Condition"):
            uncertain = True
        action = statement.get("Action", [])
        actions = action if isinstance(action, list) else [action]
        if not any(str(value).lower() in {"sts:assumerole", "sts:*", "*"} for value in actions):
            uncertain = True
        principal = statement.get("Principal")
        if isinstance(principal, dict):
            for value in principal.values():
                principals.extend(value if isinstance(value, list) else [value])
        else:
            principals.append(principal)
    values = [str(value) for value in principals if value is not None]
    broad = not values or any(value == "*" for value in values)
    external = any(
        value.isdigit() and len(value) == 12 and value != account_id
        or value.startswith("arn:") and f"::{account_id}:" not in value
        for value in values
    )
    risk = "HIGH" if broad or external or uncertain else "MEDIUM"
    reason = (
        "role trust has broad, external, or uncertain principals"
        if risk == "HIGH" else "role trust names specific principals"
    )
    return risk, reason, {
        "source": "trust_policy", "principals": values[:100],
        "conditions_or_unsupported_constructs": uncertain,
        "effective_access_evaluated": False,
    }


def evaluate_risk(event, context):
    logger.log("evaluate_risk", "start", "Starting snapshot policy risk evaluation")
    with db.get_connection() as conn:
        observations = repo.list_current_observations(conn)
        if not observations:
            return {"status": "blocked", "reason": "no_published_snapshot", "roles_updated": 0}
        assessed = 0
        verified_policies = {}
        policy_projections = {}
        for observation in observations:
            observation_id, snapshot_id, grant_id, policy_id, policy_name, document_json = observation[:6]
            policy_type = (
                "ROLE_TRUST" if observation[9] == "ROLE_TRUST"
                else "IDENTITY_CENTER" if observation[9] == "IDENTITY_CENTER_ASSIGNMENT"
                else "IDENTITY"
            )
            risk_evidence = policy_assessment.assess_document(
                document_json, policy_type, observation[7]
            )
            risk = policy_assessment.legacy_risk(risk_evidence["risk_severity"])
            reason = ", ".join(risk_evidence["reason_codes"][:3]) or "No supported concern found"
            coverage = json.loads(observation[16])
            missing = observation[11] == "MISSING"
            source_partial = not coverage.get("complete_for_declared_scope")
            grant_status = (
                "PARTIAL" if (missing or source_partial)
                and risk_evidence["assessment_status"] == "SUPPORTED"
                else risk_evidence["assessment_status"]
            )
            grant_confidence = (
                "MEDIUM" if (missing or source_partial)
                and risk_evidence["risk_severity"] != "UNKNOWN"
                else "INSUFFICIENT" if missing or source_partial
                else risk_evidence["assessment_confidence"]
            )
            grant_risk = "HIGH" if missing or source_partial else risk
            grant_evidence = {
                "schema_version": "risk-assessment-v1",
                "rule_version": evidence.POLICY_RULE_VERSION,
                "risk_severity": risk_evidence["risk_severity"],
                "assessment_status": grant_status,
                "assessment_confidence": grant_confidence,
                "manual_review_required": (
                    missing or source_partial or risk_evidence["manual_review_required"]
                ),
                "reason_codes": list(dict.fromkeys(
                    risk_evidence["reason_codes"]
                    + (["POLICY_DOCUMENT_MISSING"] if missing else [])
                )),
                "evidence_completeness": {
                    "collection_status": "COMPLETE",
                    "source_coverage": (
                        "COMPLETE" if coverage.get("complete_for_declared_scope")
                        else "PARTIAL"
                    ),
                    "unassessed_surfaces": coverage.get("unassessed_surfaces", []),
                    "document_coverage": "PARTIAL" if missing else "COMPLETE",
                    "interpretability": grant_status,
                    "missing_evidence_count": 1 if missing else 0,
                    "unsupported_constructs": risk_evidence["unsupported_constructs"],
                    "reason_codes": [observation[12]] if missing else [],
                },
                "snapshot_id": snapshot_id,
                "observation_id": observation_id,
                "grant_id": grant_id,
                "source_id": observation[13],
                "attachment_id": observation[14],
                "policy_version": observation[15],
                "policy_sha256": observation[6],
                "statement_refs": [
                    {
                        **ref, "policy_sha256": observation[6],
                        "attachment_id": observation[14],
                        "policy_version": observation[15],
                    }
                    for ref in risk_evidence["statement_refs"]
                ],
            }
            assessed_at = datetime.now(timezone.utc).isoformat()
            policy_key = (snapshot_id, policy_id, observation[6], evidence.POLICY_RULE_VERSION)
            policy_result = (
                risk, reason, evidence.canonical_json(risk_evidence)
            )
            prior = verified_policies.get(policy_key)
            if prior is not None and prior != policy_result:
                raise RuntimeError("Same snapshot policy identity produced different risk evidence")
            repo.store_snapshot_risk(
                conn, observation, risk, reason, risk_evidence,
                evidence.POLICY_RULE_VERSION, assessed_at,
                grant_evidence, grant_risk,
                policy_verified=prior is not None,
            )
            verified_policies[policy_key] = policy_result
            # Keep the final per-policy projection from scan order. The
            # append-only grant assessment above remains per observation.
            policy_projections[policy_id] = (
                grant_risk, reason, risk_evidence, assessed_at,
            )
            assessed += 1
        for policy_id, (risk_level, reason, risk_evidence, assessed_at) in policy_projections.items():
            repo.update_role_risk(conn, policy_id, risk_level)
            repo.store_risk_assessment(
                conn, policy_id, risk_level, reason, risk_evidence,
                evidence.POLICY_RULE_VERSION, assessed_at,
            )
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
