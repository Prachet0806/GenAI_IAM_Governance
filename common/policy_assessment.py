"""Versioned IAM document-pattern triage; never an authorization decision."""

import json

from common import evidence

SENSITIVE_ACTIONS = {
    "iam:passrole", "iam:createpolicyversion", "iam:attachuserpolicy",
    "iam:addusertogroup", "sts:assumerole", "secretsmanager:getsecretvalue",
    "secretsmanager:batchgetsecretvalue", "kms:decrypt",
    "ssm:getparameter", "ssm:getparameters", "ssm:getparametersbypath",
    "lambda:invokefunction", "ec2:runinstances",
    "cloudformation:executechangeset",
}
MUTATING_ACTIONS = {
    "s3:putobject", "s3:deleteobject", "ec2:startinstances",
    "ec2:stopinstances", "lambda:updatefunctioncode",
}
READ_ACTIONS = {
    "s3:getobject", "s3:listbucket", "iam:getuser", "iam:listusers",
    "ec2:describeinstances", "cloudwatch:getmetricdata",
}
SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def decode_policy_json(text: str):
    return json.loads(text, object_pairs_hook=_unique_pairs)


def parse_document(raw):
    if isinstance(raw, str):
        try:
            raw = decode_policy_json(raw)
        except (ValueError, TypeError) as exc:
            return None, "UNASSESSED", ["INVALID_JSON" if str(exc) != "DUPLICATE_JSON_KEY"
                                         else "DUPLICATE_JSON_KEY"]
    if not isinstance(raw, dict):
        return None, "UNASSESSED", ["DOCUMENT_UNAVAILABLE"]
    if raw.get("Version") != "2012-10-17":
        return raw, "UNSUPPORTED", ["UNSUPPORTED_POLICY_VERSION"]
    statements = raw.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        return raw, "UNSUPPORTED", ["EMPTY_OR_MALFORMED_STATEMENTS"]
    return {**raw, "Statement": statements}, "PARSED", []


def _strings(value):
    values = value if isinstance(value, list) else [value]
    if not values or any(not isinstance(item, str) or not item for item in values):
        return None
    return values


def _principal_values(value):
    if isinstance(value, str):
        return [value] if value else None
    if not isinstance(value, dict) or not value:
        return None
    values = []
    for item in value.values():
        parsed = _strings(item)
        if parsed is None:
            return None
        values.extend(parsed)
    return values


def assess_document(raw, policy_type: str, account_id: str) -> dict:
    """Return only document-level facts; attachment and coverage are grant-level."""
    document, parse_status, reasons = parse_document(raw)
    result = {
        "schema_version": "risk-assessment-v1",
        "rule_version": evidence.POLICY_RULE_VERSION,
        "policy_type": policy_type,
        "risk_severity": "UNKNOWN",
        "assessment_status": parse_status,
        "assessment_confidence": "INSUFFICIENT",
        "manual_review_required": True,
        "reason_codes": list(reasons),
        "statement_refs": [],
        "unsupported_constructs": [],
        "effective_access_evaluated": False,
    }
    if policy_type not in ("IDENTITY", "ROLE_TRUST", "IDENTITY_CENTER"):
        result["assessment_status"] = "UNSUPPORTED"
        result["reason_codes"] = ["UNSUPPORTED_POLICY_TYPE"]
        return result
    if parse_status != "PARSED":
        return result
    severity = "UNKNOWN"
    valid = 0
    unsupported = False
    for index, statement in enumerate(document["Statement"]):
        if not isinstance(statement, dict):
            result["reason_codes"].append("MALFORMED_STATEMENT")
            result["unsupported_constructs"].append({"statement_index": index, "construct": "Statement"})
            unsupported = True
            continue
        effect = statement.get("Effect")
        if effect not in ("Allow", "Deny"):
            result["reason_codes"].append("INVALID_EFFECT")
            result["unsupported_constructs"].append({"statement_index": index, "construct": "Effect"})
            unsupported = True
            continue
        ref = {"statement_index": index, "sid": statement.get("Sid"),
               "effect": effect, "matched_actions": [], "reason_codes": []}
        if "Sid" in statement and not isinstance(statement["Sid"], str):
            ref["reason_codes"].append("MALFORMED_SID")
            unsupported = True
        if effect == "Deny":
            ref["reason_codes"].append("DENY_PRESENT_NOT_SUBTRACTED")
            for key in ("Action", "NotAction", "Resource", "NotResource"):
                if key in statement and _strings(statement[key]) is None:
                    ref["reason_codes"].append(f"MALFORMED_{key.upper()}")
                    unsupported = True
            if "Condition" in statement and not isinstance(statement["Condition"], dict):
                ref["reason_codes"].append("MALFORMED_CONDITION")
                unsupported = True
            result["reason_codes"].extend(ref["reason_codes"])
            result["statement_refs"].append(ref)
            valid += 1
            continue
        for key in ("NotAction", "NotResource", "NotPrincipal"):
            if key in statement:
                ref["reason_codes"].append(f"UNSUPPORTED_{key.upper()}")
                result["unsupported_constructs"].append(
                    {"statement_index": index, "construct": key}
                )
                unsupported = True
        condition = statement.get("Condition")
        if condition is not None:
            if not isinstance(condition, dict):
                ref["reason_codes"].append("MALFORMED_CONDITION")
            else:
                ref["reason_codes"].append("CONDITION_PRESENT")
            result["unsupported_constructs"].append(
                {"statement_index": index, "construct": "Condition"}
            )
            unsupported = True
        actions = _strings(statement.get("Action")) if "Action" in statement else None
        resources = _strings(statement.get("Resource")) if "Resource" in statement else None
        if actions is None:
            ref["reason_codes"].append("MALFORMED_OR_MISSING_ACTION")
            unsupported = True
        if policy_type != "ROLE_TRUST" and resources is None:
            ref["reason_codes"].append("MALFORMED_OR_MISSING_RESOURCE")
            unsupported = True
        if policy_type == "ROLE_TRUST":
            principals = _principal_values(statement.get("Principal"))
            if principals is None:
                ref["reason_codes"].append("MALFORMED_OR_MISSING_PRINCIPAL")
                unsupported = True
            elif actions is not None:
                if not any(action.lower() in ("sts:assumerole", "sts:*", "*")
                           for action in actions):
                    ref["reason_codes"].append("TRUST_ACTION_UNRECOGNIZED")
                    unsupported = True
                elif "*" in principals:
                    severity = max((severity, "HIGH"), key=SEVERITY_ORDER.get)
                    ref["reason_codes"].append("BROAD_TRUST_PRINCIPAL")
                elif any(
                    (value.isdigit() and len(value) == 12 and value != account_id)
                    or (value.startswith("arn:") and f"::{account_id}:" not in value)
                    for value in principals
                ):
                    severity = max((severity, "HIGH"), key=SEVERITY_ORDER.get)
                    ref["reason_codes"].append("EXTERNAL_TRUST_PRINCIPAL")
                else:
                    severity = max((severity, "MEDIUM"), key=SEVERITY_ORDER.get)
                    ref["reason_codes"].append("SPECIFIC_TRUST_PRINCIPAL")
            ref["principal_values"] = principals or []
        elif actions is not None:
            if "Principal" in statement:
                ref["reason_codes"].append("UNEXPECTED_PRINCIPAL")
                unsupported = True
            for action in actions:
                normalized = action.lower()
                if normalized == "*" and resources is not None and "*" in resources and condition is None:
                    found, code = "CRITICAL", "FULL_WILDCARD_IDENTITY_POLICY"
                elif "*" in normalized or "?" in normalized:
                    found, code = "HIGH", "WILDCARD_ACTION"
                elif normalized in SENSITIVE_ACTIONS or (
                    normalized.startswith("iam:")
                    and not normalized.split(":", 1)[1].startswith(("get", "list"))
                ):
                    found, code = "HIGH", "SENSITIVE_ACTION"
                elif normalized in MUTATING_ACTIONS:
                    found, code = "MEDIUM", "MUTATING_ACTION"
                elif normalized in READ_ACTIONS:
                    found, code = (
                        ("MEDIUM", "BROAD_READ_RESOURCE") if "*" in resources
                        else ("LOW", "REVIEWED_READ_ACTION")
                    ) if resources is not None else ("UNKNOWN", "RESOURCE_CONTEXT_MISSING")
                else:
                    found, code = "UNKNOWN", "UNKNOWN_ACTION"
                    unsupported = True
                severity = max((severity, found), key=SEVERITY_ORDER.get)
                ref["matched_actions"].append(action)
                ref["reason_codes"].append(code)
                if found in ("HIGH", "CRITICAL") and resources is not None and "*" not in resources:
                    ref["reason_codes"].append("RESOURCE_SCOPE_NOT_EVALUATED")
                    unsupported = True
        result["statement_refs"].append(ref)
        result["reason_codes"].extend(ref["reason_codes"])
        valid += 1
    if unsupported and severity == "LOW":
        severity = "UNKNOWN"
        result["reason_codes"].append("LOW_CONCLUSION_BLOCKED_BY_UNCERTAINTY")
    if severity == "UNKNOWN" and valid and not unsupported:
        result["reason_codes"].append("NO_ANALYZABLE_ALLOW")
    result["risk_severity"] = severity
    result["reason_codes"] = list(dict.fromkeys(result["reason_codes"]))
    result["assessment_status"] = (
        "PARTIAL" if unsupported and valid
        else "UNSUPPORTED" if unsupported
        else "SUPPORTED" if severity != "UNKNOWN"
        else "UNASSESSED"
    )
    result["assessment_confidence"] = (
        "MEDIUM" if unsupported and severity != "UNKNOWN"
        else "HIGH" if not unsupported and severity != "UNKNOWN"
        else "INSUFFICIENT"
    )
    result["manual_review_required"] = (
        unsupported or severity in ("UNKNOWN", "HIGH", "CRITICAL")
    )
    return result


def legacy_risk(severity: str) -> str:
    return severity if severity in ("LOW", "MEDIUM", "HIGH") else "HIGH"
