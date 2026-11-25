"""Stateless, template-rendered questions about one pinned grant path."""

from common.ai.validation import CLAIM_TYPES, expected_claims, validate_claim

INTENTS = {"ATTACHMENT", "RULE", "LIMITATIONS", "NEXT_EVIDENCE"}
LIMITATION = (
    "This describes an observed grant path and rule triage only. "
    "Effective access, business need, and change safety were not evaluated."
)
UNSUPPORTED = (
    "The pinned evidence cannot answer that question. Inspect the source evidence "
    "and escalate questions about effective access or operational impact."
)


def _claim(bundle: dict, kind: str) -> dict:
    binding = bundle["binding"]
    return validate_claim(bundle, {
        "type": kind,
        "subject": binding["grant_id"],
        "value": expected_claims(bundle)[kind],
        "evidence_id": binding[CLAIM_TYPES[kind]],
        "manifest_sha256": bundle["manifest_sha256"],
    })


def abstain(bundle: dict) -> dict:
    claim = _claim(bundle, "AUTHORIZATION_NOT_EVALUATED")
    return {
        "status": "ABSTAINED", "intent": "UNSUPPORTED", "answer": UNSUPPORTED,
        "limitations": LIMITATION, "claims": [claim],
        "evidence": {
            "retrieved": [bundle["binding"]["snapshot_id"], bundle["binding"]["observation_id"], claim["evidence_id"]],
            "considered": [claim["evidence_id"]], "cited": [claim["evidence_id"]],
            "unavailable": [],
        },
        "review_manifest_sha256": bundle["manifest_sha256"],
        "source": "DETERMINISTIC_TEMPLATE",
    }


def answer(bundle: dict, intent: str) -> dict:
    if intent not in INTENTS:
        raise ValueError("Unsupported question intent")
    facts = expected_claims(bundle)
    binding = bundle["binding"]
    selected = ["AUTHORIZATION_NOT_EVALUATED"]
    if intent == "ATTACHMENT":
        selected.insert(0, "POLICY_ATTACHMENT_OBSERVED")
        if "GROUP_MEMBERSHIP_OBSERVED" in facts:
            selected.insert(1, "GROUP_MEMBERSHIP_OBSERVED")
        answer_text = (
            "The pinned observation records a " + binding["grant_type"].replace("_", " ").lower()
            + " grant path for this policy attachment. The frozen policy hash and observation time "
            "are in the cited evidence."
        )
    elif intent == "RULE":
        selected += [kind for kind in ("TRUST_STATEMENT_OBSERVED", "WILDCARD_PATTERN_DETECTED", "CONDITION_PRESENT", "ASSESSMENT_INCOMPLETE") if kind in facts]
        phrases = []
        if "TRUST_STATEMENT_OBSERVED" in facts:
            phrases.append("The pinned assessment captures a role trust statement")
        if "WILDCARD_PATTERN_DETECTED" in facts:
            phrases.append("the rule detected a wildcard pattern")
        if "CONDITION_PRESENT" in facts:
            phrases.append("a condition is present but its authorization effect was not evaluated")
        if "ASSESSMENT_INCOMPLETE" in facts:
            phrases.append("the pinned assessment is incomplete or unsupported")
        answer_text = (
            "; ".join(phrases) + ". Inspect the exact cited statement and rule version."
            if phrases else UNSUPPORTED
        )
    elif intent == "LIMITATIONS":
        selected += [kind for kind in ("POLICY_DOCUMENT_MISSING", "SOURCE_SCAN_INCOMPLETE") if kind in facts]
        answer_text = (
            "The cited assessment does not evaluate authorization. "
            "The cited evidence also records a missing document or incomplete source scan."
            if len(selected) > 1 else LIMITATION
        )
    else:
        selected += [kind for kind in ("POLICY_DOCUMENT_MISSING", "SOURCE_SCAN_INCOMPLETE") if kind in facts]
        answer_text = (
            "Inspect the cited frozen attachment, statement, rule reasons, and source coverage. "
            "Escalate missing evidence and business need to the responsible owner."
        )
        selected.insert(0, "POLICY_ATTACHMENT_OBSERVED")
    try:
        claims = [_claim(bundle, kind) for kind in selected]
    except (KeyError, ValueError, TypeError):
        claims = [_claim(bundle, "AUTHORIZATION_NOT_EVALUATED")]
        answer_text = UNSUPPORTED
    return {
        "status": "ABSTAINED" if answer_text == UNSUPPORTED else "ANSWERED",
        "intent": intent,
        "answer": answer_text,
        "limitations": LIMITATION,
        "claims": claims,
        "evidence": {
            "retrieved": [binding["snapshot_id"], binding["observation_id"], binding["risk_assessment_id"]],
            "considered": [binding["snapshot_id"], binding["observation_id"], binding["risk_assessment_id"]],
            "cited": list(dict.fromkeys(claim["evidence_id"] for claim in claims)),
            "unavailable": [],
        },
        "review_manifest_sha256": bundle["manifest_sha256"],
        "source": "DETERMINISTIC_TEMPLATE",
    }
