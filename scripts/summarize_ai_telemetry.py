"""Summarize redacted Q&A and provider-attempt JSON logs without evidence IDs."""

import argparse
import json
import math
from collections import Counter
from pathlib import Path


def percentile(values: list[int], fraction: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def summarize(lines: list[str]) -> dict:
    groups: dict[str, list[dict]] = {"review_qa": [], "ai_explanation": []}
    for line in lines:
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(event, dict) or event.get("action") not in groups:
            continue
        if event["action"] == "ai_explanation" and event.get("status") != "provider_result":
            continue
        groups[event["action"]].append(event)
    result = {}
    for name, events in groups.items():
        latencies = [value for event in events
                     if type(value := (event.get("details") or {}).get("latency_ms")) is int and value >= 0]
        result[name] = {
            "events": len(events),
            "outcomes": dict(Counter(event.get("status", "unknown") for event in events)),
            "p50_latency_ms": percentile(latencies, .50),
            "p95_latency_ms": percentile(latencies, .95),
            "measured_latency_events": len(latencies),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(summarize(args.input.read_text(encoding="utf-8").splitlines()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
