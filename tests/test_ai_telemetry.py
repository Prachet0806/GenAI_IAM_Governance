"""Telemetry aggregation never projects identities or evidence fingerprints."""

import json

from scripts.summarize_ai_telemetry import summarize


def test_summary_reports_abstentions_and_latency_without_evidence():
    events = [
        {"action": "review_qa", "status": "answered", "details": {
            "latency_ms": 10, "evidence_fingerprints": {"cited": ["secret-fingerprint"]}}},
        {"action": "review_qa", "status": "abstained", "details": {"latency_ms": 100}},
        {"action": "ai_explanation", "status": "provider_result", "details": {"latency_ms": 50}},
    ]
    result = summarize([json.dumps(event) for event in events])
    assert result["review_qa"]["events"] == 2
    assert result["review_qa"]["outcomes"]["abstained"] == 1
    assert result["review_qa"]["p50_latency_ms"] == 10
    assert result["review_qa"]["p95_latency_ms"] == 100
    assert result["ai_explanation"]["p95_latency_ms"] == 50
    assert "secret-fingerprint" not in json.dumps(result)
