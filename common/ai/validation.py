"""Validate proposed claims against independently retrieved pinned facts."""

CLAIM_TYPES = {
    "POLICY_ATTACHMENT_OBSERVED": "observation_id",
    "GROUP_MEMBERSHIP_OBSERVED": "observation_id",
    "TRUST_STATEMENT_OBSERVED": "risk_assessment_id",
    "WILDCARD_PATTERN_DETECTED": "risk_assessment_id",
    "CONDITION_PRESENT": "risk_assessment_id",
    "POLICY_DOCUMENT_MISSING": "observation_id",
    "SOURCE_SCAN_INCOMPLETE": "snapshot_id",
    "AUTHORIZATION_NOT_EVALUATED": "risk_assessment_id",
    "ASSESSMENT_INCOMPLETE": "risk_assessment_id",
}


def expected_claims(bundle: dict) -> dict:
    binding = bundle["binding"]
    assessment = bundle["assessment"]
    completeness = assessment.get("evidence_completeness") or {}
    reason_codes = assessment.get("reason_codes") or []
    result = {
        "POLICY_ATTACHMENT_OBSERVED": {
            "grant_type": binding["grant_type"],
            "attachment_id": binding["attachment_id"],
            "policy_sha256": binding["policy_sha256"],
            "observed_at": binding["observed_at"],
        },
        "AUTHORIZATION_NOT_EVALUATED": {"status": "not_evaluated"},
    }
    if assessment.get("assessment_status") != "SUPPORTED":
        result["ASSESSMENT_INCOMPLETE"] = {
            "assessment_status": assessment.get("assessment_status"),
            "reason_codes": list(reason_codes),
        }
    if binding["grant_type"].startswith("GROUP_"):
        result["GROUP_MEMBERSHIP_OBSERVED"] = {
            "principal_id": binding["principal_id"],
            "group_id": binding["source_id"],
            "attachment_id": binding["attachment_id"],
            "policy_sha256": binding["policy_sha256"],
            "observed_at": binding["observed_at"],
        }
    if any("WILDCARD" in code for code in reason_codes):
        result["WILDCARD_PATTERN_DETECTED"] = {
            "reason_codes": sorted(code for code in reason_codes if "WILDCARD" in code),
        }
    if binding["grant_type"] == "ROLE_TRUST" and assessment.get("statement_refs"):
        result["TRUST_STATEMENT_OBSERVED"] = {
            "statement_indexes": sorted({
                ref["statement_index"] for ref in assessment["statement_refs"]
            }),
            "policy_sha256": binding["policy_sha256"],
        }
    if "CONDITION_PRESENT" in reason_codes:
        result["CONDITION_PRESENT"] = {"status": "present_not_evaluated"}
    if binding["evidence_status"] == "MISSING":
        result["POLICY_DOCUMENT_MISSING"] = {
            "evidence_status": binding["evidence_status"],
        }
    coverage = bundle["coverage"] or {}
    if coverage.get("complete_for_declared_scope") is not True:
        result["SOURCE_SCAN_INCOMPLETE"] = {"status": "incomplete_or_unknown"}
    return result


def validate_claim(bundle: dict, claim: dict) -> dict:
    if not isinstance(claim, dict) or set(claim) != {
        "type", "subject", "value", "evidence_id", "manifest_sha256"
    }:
        raise ValueError("Claim schema mismatch")
    kind = claim["type"]
    binding = bundle["binding"]
    if kind not in CLAIM_TYPES or kind not in expected_claims(bundle):
        raise ValueError("Claim is not supported by pinned evidence")
    if claim["manifest_sha256"] != bundle["manifest_sha256"]:
        raise ValueError("Claim manifest mismatch")
    if claim["subject"] != binding["grant_id"]:
        raise ValueError("Claim subject mismatch")
    if claim["evidence_id"] != binding[CLAIM_TYPES[kind]]:
        raise ValueError("Claim evidence mismatch")
    if claim["value"] != expected_claims(bundle)[kind]:
        raise ValueError("Claim value mismatch")
    return claim
