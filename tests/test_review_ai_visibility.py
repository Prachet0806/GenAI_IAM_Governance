"""Authorized reviewer visibility of the legacy AI summary compatibility view."""

import hashlib
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.review_service import app
from common import auth, repo
from common.db import db
from scripts import migrate


def _seed(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path / 'review_visibility.db'}")
    monkeypatch.setenv("REVIEWER_GROUP", "reviewers")
    migrate.apply_sqlite()
    with db.get_connection() as conn:
        repo.insert_user(conn, "U1", "alice@example.com", "arn:aws:iam::123:user/alice", "2026-01-01T00:00:00+00:00")
        repo.insert_role(conn, "R1", "ReadOnlyAccess", "LOW")
        repo.insert_role(conn, "R2", "AnotherPolicy", "LOW")
        for campaign_id, review_id, role_id in (("C1", "REV1", "R1"), ("C2", "REV2", "R2")):
            repo.create_campaign(conn, campaign_id, campaign_id, "2026-01-01T00:00:00+00:00")
            repo.create_review(conn, review_id, campaign_id, "U1", role_id, "2026-01-01T00:00:00+00:00")
        repo.assign_campaign_reviewer(conn, "C1", "assigned", "admin")

    def verify_token(token):
        if token == "invalid":
            raise auth.AuthenticationError("invalid")
        if token == "wrong-group":
            return {"sub": "assigned", "groups": []}
        return {"sub": token, "groups": ["reviewers"]}

    monkeypatch.setattr(auth, "verify_access_token", verify_token)
    return TestClient(app)


def _get(client, review_id="REV1", token="assigned"):
    return client.get(f"/reviews/{review_id}", headers={"Authorization": f"Bearer {token}"})


def _record_generation(conn, generation_id, summary, when, *, source="MODEL", output_hash=None):
    repo.record_ai_generation(
        conn, generation_id, "REV1", source, "SUCCESS",
        "example-model" if source == "MODEL" else None,
        "v1", "input-hash",
        output_hash or hashlib.sha256(summary.encode("utf-8")).hexdigest(),
        summary, when,
    )


def test_missing_and_legacy_column_only_summary(tmp_path, monkeypatch):
    client = _seed(tmp_path, monkeypatch)
    missing = _get(client)
    assert missing.status_code == 200
    assert missing.json()["ai_explanation"] == {
        "status": "missing", "authority": "legacy_compatibility",
        "summary": None, "provenance_state": "missing",
        "generation_id": None, "source": None, "model": None,
        "prompt_version": None, "generated_at": None,
        "validated_artifact": False,
    }

    with db.get_connection() as conn:
        db.execute(conn.cursor(), "UPDATE access_reviews SET ai_risk_summary=? WHERE review_id='REV1'", ("Historic explanation",))
    old = _get(client)
    assert old.status_code == 200
    assert old.json()["ai_explanation"]["summary"] == "Historic explanation"
    assert old.json()["ai_explanation"]["provenance_state"] == "column_only"


def test_matching_generation_provenance_and_fallback(tmp_path, monkeypatch):
    client = _seed(tmp_path, monkeypatch)
    with db.get_connection() as conn:
        db.execute(conn.cursor(), "UPDATE access_reviews SET ai_risk_summary=? WHERE review_id='REV1'", ("Review this grant",))
        _record_generation(conn, "GEN1", "Review this grant", "2026-01-02T00:00:00+00:00")
    explanation = _get(client).json()["ai_explanation"]
    assert explanation["summary"] == "Review this grant"
    assert explanation["provenance_state"] == "matched_generation"
    assert explanation["generation_id"] == "GEN1"
    assert explanation["source"] == "MODEL"
    assert explanation["model"] == "example-model"
    assert explanation["prompt_version"] == "v1"
    assert explanation["validated_artifact"] is False

    with db.get_connection() as conn:
        db.execute(conn.cursor(), "UPDATE access_reviews SET ai_risk_summary=? WHERE review_id='REV1'", ("Fallback explanation",))
        _record_generation(conn, "GEN2", "Fallback explanation", "2026-01-03T00:00:00+00:00", source="FALLBACK")
    fallback = _get(client).json()["ai_explanation"]
    assert fallback["source"] == "FALLBACK"
    assert fallback["model"] is None
    assert fallback["provenance_state"] == "matched_generation"


def test_multiple_generations_do_not_misattribute_column_summary(tmp_path, monkeypatch):
    client = _seed(tmp_path, monkeypatch)
    with db.get_connection() as conn:
        db.execute(conn.cursor(), "UPDATE access_reviews SET ai_risk_summary=? WHERE review_id='REV1'", ("First",))
        _record_generation(conn, "GEN1", "First", "2026-01-02T00:00:00+00:00")
        _record_generation(conn, "GEN2", "Second", "2026-01-03T00:00:00+00:00")
    explanation = _get(client).json()["ai_explanation"]
    assert explanation["generation_id"] == "GEN1"
    assert explanation["provenance_state"] == "older_matching_generation"

    with db.get_connection() as conn:
        db.execute(conn.cursor(), "UPDATE access_reviews SET ai_risk_summary=? WHERE review_id='REV1'", ("Unmatched",))
    unmatched = _get(client).json()["ai_explanation"]
    assert unmatched["summary"] == "Unmatched"
    assert unmatched["generation_id"] is None
    assert unmatched["provenance_state"] == "no_matching_generation"


def test_generation_hash_mismatch_is_labelled_unverified(tmp_path, monkeypatch):
    client = _seed(tmp_path, monkeypatch)
    with db.get_connection() as conn:
        db.execute(conn.cursor(), "UPDATE access_reviews SET ai_risk_summary=? WHERE review_id='REV1'", ("Changed text",))
        _record_generation(conn, "GEN1", "Changed text", "2026-01-02T00:00:00+00:00", output_hash="incorrect")
    explanation = _get(client).json()["ai_explanation"]
    assert explanation["generation_id"] == "GEN1"
    assert explanation["provenance_state"] == "generation_unverified"
    assert explanation["validated_artifact"] is False


def test_reviewer_api_requires_token_group_and_campaign_assignment(tmp_path, monkeypatch):
    client = _seed(tmp_path, monkeypatch)
    with db.get_connection() as conn:
        db.execute(conn.cursor(), "UPDATE access_reviews SET ai_risk_summary=? WHERE review_id='REV2'", ("Other campaign secret",))
    assert client.get("/reviews/REV1").status_code == 401
    assert _get(client, token="invalid").status_code == 401
    assert _get(client, token="wrong-group").status_code == 403
    assert _get(client, token="unassigned").status_code == 403
    cross_campaign = _get(client, review_id="REV2")
    assert cross_campaign.status_code == 403
    assert "Other campaign secret" not in cross_campaign.text
