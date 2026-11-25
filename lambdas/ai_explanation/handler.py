"""Durable, advisory explanation worker. It writes only AI jobs and artifacts."""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import ai_artifacts, config, evidence, logger
from common.ai import provider_controls
from common.db import db

MAX_INPUT_BYTES = 48_000
MAX_OUTPUT_BYTES = 16_000
SYSTEM_PROMPT = provider_controls.SYSTEM_PROMPT


class ProviderCircuitOpen(RuntimeError):
    pass


def _get_client():
    if (
        not config.is_genai_enabled()
        or not os.getenv("GOOGLE_API_KEY")
        or os.getenv("AI_PROVIDER_DATA_APPROVED", "").lower() != "true"
        or not os.getenv("AI_PSEUDONYM_KEY")
    ):
        return None
    try:
        provider_controls.current_approval(model=config.get_genai_model(), prompt=provider_controls.PROMPT_PREFIX)
    except provider_controls.ApprovalRejected:
        return None
    try:
        from google import genai
        from google.genai import types

        return genai.Client(
            api_key=os.environ["GOOGLE_API_KEY"],
            http_options=types.HttpOptions(
                timeout=12_000,
                retry_options=types.HttpRetryOptions(
                    attempts=2, initial_delay=0.2, max_delay=0.2, jitter=0.1
                ),
            ),
        )
    except Exception as exc:
        logger.log(
            "ai_explanation", "warn", "Provider client unavailable",
            level="WARN", details={"error_type": type(exc).__name__},
        )
        return None


def _generate(client, context: dict, model: str):
    payload = provider_controls.provider_payload(context)
    approval = provider_controls.current_approval(
        model=model, prompt=provider_controls.PROMPT_PREFIX, payload=payload,
        account_id=context.get("source_account_id"),
    )
    input_json = evidence.canonical_json(payload)
    if len(input_json.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError("Evidence exceeds provider input limit")
    response = client.models.generate_content(
        model=model,
        contents=provider_controls.PROMPT_PREFIX + input_json,
        config=provider_controls.GENERATION_CONFIG,
    )
    raw = getattr(response, "text", None)
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("Provider response missing or too large")
    output = ai_artifacts.validate_output(
        json.loads(raw), context["allowed_evidence_ids"]
    )
    usage = getattr(response, "usage_metadata", None)
    return output, {
        "input_tokens": getattr(usage, "prompt_token_count", None),
        "output_tokens": getattr(usage, "candidates_token_count", None),
        "provider_input_sha256": ai_artifacts._hash(input_json),
        "approval_version": approval["approval_version"],
        "prompt_sha256": provider_controls.prompt_sha256(provider_controls.PROMPT_PREFIX),
        "provider_region": provider_controls.REGION,
    }


def _enqueue_pending(limit: int):
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(
            cur,
            """SELECT r.review_id FROM access_reviews r
               JOIN grant_risk_assessments gra ON gra.assessment_id=r.risk_assessment_id
               WHERE r.status='PENDING' AND r.snapshot_id IS NOT NULL
                 AND gra.risk_level='HIGH'
                 AND NOT EXISTS (
                    SELECT 1 FROM ai_jobs j WHERE j.review_id=r.review_id
                      AND j.prompt_version=? AND j.schema_version=?
                      AND j.provider_model=?
                 ) ORDER BY r.created_at,r.review_id LIMIT ?""",
            (ai_artifacts.PROMPT_VERSION, ai_artifacts.SCHEMA_VERSION,
             config.get_genai_model(), limit),
        )
        ids = [row[0] for row in cur.fetchall()]
        return [
            ai_artifacts.enqueue_review(
                conn, review_id, pseudonym_key=os.getenv("AI_PSEUDONYM_KEY")
            )
            for review_id in ids
        ]


def _process(job_id: str | None, client):
    with db.get_connection() as conn:
        job = ai_artifacts.claim_job(conn, job_id=job_id)
    if not job:
        return {"status": "IDLE", "job_id": job_id}
    if job["prompt_version"] != ai_artifacts.PROMPT_VERSION:
        with db.get_connection() as conn:
            retired = ai_artifacts.retire_job(conn, job, error_code="prompt_version_retired")
        return {"status": "FAILED" if retired else "STALE", "job_id": job["job_id"],
                "reason": "prompt_version_retired"}
    started = time.monotonic()
    with db.get_connection() as conn:
        context = ai_artifacts.build_context(
            conn, job["review_id"], pseudonym_key=os.getenv("AI_PSEUDONYM_KEY")
        )
    if not context or (
        context["snapshot_id"], context["observation_id"],
        context["risk_assessment_id"]
    ) != (
        job["snapshot_id"], job["observation_id"], job["risk_assessment_id"]
    ) or ai_artifacts._hash(evidence.canonical_json(context)) != job["input_sha256"]:
        with db.get_connection() as conn:
            status = ai_artifacts.fail_or_retry(
                conn, job, error_code="context_unavailable", latency_ms=0
            )
        return {"status": status, "job_id": job["job_id"], "reason": "context_unavailable"}
    try:
        model = job["provider_model"] or config.get_genai_model()
        with db.get_connection() as conn:
            if ai_artifacts.provider_circuit_open(conn, model):
                raise ProviderCircuitOpen("Recent provider transport failures opened the circuit")
        output, usage = _generate(client, context, model)
        latency_ms = int((time.monotonic() - started) * 1000)
        with db.get_connection() as conn:
            accepted = ai_artifacts.complete_job(
                conn, job, output, source="MODEL", provider="google",
                model=model, latency_ms=latency_ms,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                provider_provenance={
                    "approval_version": usage["approval_version"],
                    "provider_region": usage["provider_region"],
                    "prompt_sha256": usage["prompt_sha256"],
                    "provider_input_sha256": usage["provider_input_sha256"],
                    "input_classes": sorted(provider_controls.INPUT_CLASSES),
                },
            )
        logger.log(
            "ai_explanation", "provider_result", "Explanation provider attempt completed",
            details={"job_id": job["job_id"], "approval_version": usage["approval_version"],
                     "provider_input_sha256": usage["provider_input_sha256"],
                     "template_sha256": usage["prompt_sha256"],
                     "provider_region": usage["provider_region"],
                     "latency_ms": latency_ms},
        )
        return {"status": "SUCCEEDED" if accepted else "STALE", "job_id": job["job_id"]}
    except Exception as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        error_code = (
            "privacy_rejected" if isinstance(exc, provider_controls.ApprovalRejected)
            else "circuit_open" if isinstance(exc, ProviderCircuitOpen)
            else "output_invalid" if isinstance(exc, (ValueError, json.JSONDecodeError))
            else "provider_unavailable"
        )
        logger.log(
            "ai_explanation", "warn", "Explanation attempt failed",
            level="WARN", entity_type="ai_job", entity_id=job["job_id"],
            details={"error_code": error_code, "error_type": type(exc).__name__},
        )
        if error_code in {"privacy_rejected", "circuit_open"} or job["attempt_count"] >= job["max_attempts"]:
            with db.get_connection() as conn:
                accepted = ai_artifacts.complete_job(
                    conn, job, ai_artifacts.fallback_output(context),
                    source="FALLBACK", provider=None, model=None,
                    latency_ms=latency_ms, error_code=error_code,
                )
            return {"status": "FALLBACK" if accepted else "STALE", "job_id": job["job_id"]}
        with db.get_connection() as conn:
            status = ai_artifacts.fail_or_retry(
                conn, job, error_code=error_code, latency_ms=latency_ms
            )
        return {"status": status, "job_id": job["job_id"], "reason": error_code}


def handler(event, context):
    client = _get_client()
    if client is None:
        return {"status": "DISABLED", "reason": "GenAI or privacy gate disabled"}
    event = event if isinstance(event, dict) else {}
    review_id = event.get("review_id")
    if review_id:
        with db.get_connection() as conn:
            job = ai_artifacts.enqueue_review(
                conn, str(review_id), pseudonym_key=os.getenv("AI_PSEUDONYM_KEY")
            )
        if not job:
            return {"status": "SKIPPED", "reason": "review_not_eligible"}
        return _process(job["job_id"], client)
    limit = config.get_ai_max_calls_per_invocation()
    _enqueue_pending(limit)
    results = []
    for _ in range(limit):
        result = _process(None, client)
        if result["status"] == "IDLE":
            break
        results.append(result)
    return {"status": "SUCCESS", "processed": results}


if __name__ == "__main__":
    print(handler(None, None))
