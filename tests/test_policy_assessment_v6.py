"""Independent security scenarios for document triage and grant evidence."""

from common.policy_assessment import assess_document, decode_policy_json, legacy_risk


def _policy(action, resource="arn:aws:s3:::private/*", **extra):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action,
                       "Resource": resource, **extra}],
    }


def test_full_wildcard_is_critical_pattern_without_effective_access_claim():
    result = assess_document(_policy("*", "*"), "IDENTITY", "123456789012")
    assert (result["risk_severity"], result["assessment_status"],
            result["assessment_confidence"]) == ("CRITICAL", "SUPPORTED", "HIGH")
    assert result["effective_access_evaluated"] is False
    assert legacy_risk(result["risk_severity"]) == "HIGH"


def test_iam_wildcard_with_resource_constraint_stays_high():
    result = assess_document(_policy("iam:*"), "IDENTITY", "123456789012")
    assert result["risk_severity"] == "HIGH"
    assert "WILDCARD_ACTION" in result["reason_codes"]
    assert result["assessment_status"] == "PARTIAL"
    assert result["assessment_confidence"] == "MEDIUM"


def test_unknown_action_and_unsupported_construct_block_low():
    result = assess_document(
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::private/object"},
            {"Effect": "Allow", "Action": "newservice:DoThing", "Resource": "*"},
        ]}, "IDENTITY", "123456789012",
    )
    assert result["risk_severity"] == "UNKNOWN"
    assert result["assessment_status"] == "PARTIAL"
    assert result["manual_review_required"]
    assert "UNKNOWN_ACTION" in result["reason_codes"]


def test_known_high_survives_unsupported_sibling_and_deny():
    result = assess_document(
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
            {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        ]}, "IDENTITY", "123456789012",
    )
    assert result["risk_severity"] == "HIGH"
    assert result["assessment_status"] == "PARTIAL"
    assert result["assessment_confidence"] == "MEDIUM"
    assert len(result["statement_refs"]) == 3
    assert "DENY_PRESENT_NOT_SUBTRACTED" in result["statement_refs"][1]["reason_codes"]


def test_known_high_survives_notresource_on_same_statement():
    result = assess_document(
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "iam:PassRole",
            "NotResource": "arn:aws:iam::123456789012:role/Excluded",
        }]}, "IDENTITY", "123456789012",
    )
    assert result["risk_severity"] == "HIGH"
    assert result["assessment_status"] == "PARTIAL"
    assert "UNSUPPORTED_NOTRESOURCE" in result["reason_codes"]


def test_wildcard_trust_is_distinct_from_identity_wildcard():
    result = assess_document(
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*",
        }]}, "ROLE_TRUST", "123456789012",
    )
    assert result["risk_severity"] == "HIGH"
    assert "BROAD_TRUST_PRINCIPAL" in result["reason_codes"]
    assert "FULL_WILDCARD_IDENTITY_POLICY" not in result["reason_codes"]


def test_parser_rejects_duplicate_keys_and_unsupported_version():
    try:
        decode_policy_json(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Action":"s3:GetObject","Action":"*","Resource":"*"}]}'
        )
    except ValueError as exc:
        assert str(exc) == "DUPLICATE_JSON_KEY"
    else:
        raise AssertionError("Duplicate policy key was accepted")
    result = assess_document(_policy("s3:GetObject") | {"Version": "2008-10-17"},
                             "IDENTITY", "123456789012")
    assert result["risk_severity"] == "UNKNOWN"
    assert result["assessment_status"] == "UNSUPPORTED"


def test_malformed_types_are_not_stringified_into_rules():
    result = assess_document(
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": {"unexpected": "iam:*"},
            "Resource": True,
        }]}, "IDENTITY", "123456789012",
    )
    assert result["risk_severity"] == "UNKNOWN"
    assert result["assessment_status"] == "PARTIAL"
    assert "MALFORMED_OR_MISSING_ACTION" in result["reason_codes"]
