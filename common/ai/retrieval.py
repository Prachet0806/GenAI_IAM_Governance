"""Retrieve only the evidence frozen for one review."""

import json

from common import evidence_manifest, repo


def pinned_review(conn, review_id: str) -> dict | None:
    binding = repo.review_evidence_binding(conn, review_id)
    if binding is None:
        return None
    manifest = evidence_manifest.review_manifest(conn, review_id)
    if manifest is None:
        return None
    assessment = repo.review_assessment_payload(conn, review_id)
    row = repo.fetch_review_ai_context(conn, review_id)
    if assessment is None or row is None:
        return None
    if not isinstance(assessment.get("reason_codes"), list) or not isinstance(assessment.get("evidence_completeness"), dict):
        return None
    coverage = json.loads(row[22]) if row[22] else None
    if coverage is not None and not isinstance(coverage, dict):
        return None
    # This is a read-only, review-local projection. A newer scan cannot replace it.
    return {
        "binding": binding,
        "manifest_sha256": manifest["sha256"],
        "assessment": assessment,
        "coverage": coverage,
        "review_status": row[1],
    }
