"""Privacy-preserving, per-turn Q&A evidence and outcome telemetry."""

import hashlib
import hmac
import os

from common import logger


def telemetry_key() -> str | None:
    value = os.getenv("AI_TELEMETRY_KEY", "")
    return value if len(value.encode("utf-8")) >= 32 else None


def _fingerprints(values: list[str], key: str) -> list[str]:
    return [hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
            for value in values]


def log_review_qa_turn(
    *, request_id: str, intent: str, result: dict, latency_ms: int, key: str,
) -> None:
    evidence = result["evidence"]
    logger.log(
        "review_qa", result["status"].lower(), "Review question evaluated",
        details={
            "request_id": request_id,
            "intent": intent if intent in {"ATTACHMENT", "RULE", "LIMITATIONS", "NEXT_EVIDENCE"} else "UNSUPPORTED",
            "latency_ms": max(0, latency_ms),
            "source": result["source"],
            "evidence_fingerprints": {
                category: _fingerprints(evidence[category], key)
                for category in ("retrieved", "considered", "cited", "unavailable")
            },
        },
    )
