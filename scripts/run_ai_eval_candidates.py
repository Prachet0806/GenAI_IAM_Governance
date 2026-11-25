"""Run approved frozen cases through the explanation worker's provider boundary.

This intentionally makes real provider calls only with --execute, reviewed cases,
and a current versioned approval. It does not mark a release gate as passed.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

from common import ai_artifacts, config
from common.ai import provider_controls
from lambdas.ai_explanation import handler as worker
from scripts.evaluate_ai_explanations import fixture_sha256, read_jsonl

ROOT = Path(__file__).resolve().parents[1]


def validate_cases(cases: list[dict]) -> None:
    if (not cases or any(not isinstance(case.get("case_id"), str) or not case["case_id"] for case in cases)
            or len({case["case_id"] for case in cases}) != len(cases)):
        raise ValueError("Frozen cases must have distinct IDs")
    for case in cases:
        if case.get("dataset") not in {"synthetic", "adversarial", "historical"}:
            raise ValueError("Unknown evaluation dataset")
        if case.get("dataset") in {"synthetic", "adversarial"} and case.get("reviewed") is not True:
            raise ValueError("Synthetic and adversarial cases need independent review before provider submission")
        if case.get("dataset") == "historical" and case.get("approved") is not True:
            raise ValueError("Historical cases need explicit de-identification and data approval")
        context = case.get("context")
        if not isinstance(context, dict) or case.get("input_sha256") != ai_artifacts._hash(ai_artifacts._canonical(context)):
            raise ValueError("Case input hash does not match frozen context")
        if case.get("eligible") is True:
            provider_controls.provider_payload(context)


def run(cases: list[dict], client, approval: dict, model: str) -> tuple[dict, list[dict]]:
    digest = fixture_sha256(cases)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = {
        "commit_sha": commit, "worker": "lambdas.ai_explanation.handler",
        "model": model, "region": provider_controls.REGION,
        "prompt_version": ai_artifacts.PROMPT_VERSION,
        "schema_version": ai_artifacts.SCHEMA_VERSION,
        "approval_version": approval["approval_version"],
        "fixture_sha256": digest,
    }
    outputs = []
    for case in cases:
        if case.get("eligible") is not True:
            continue
        current = provider_controls.current_approval(
            model=model, prompt=provider_controls.PROMPT_PREFIX,
        )
        if current["approval_version"] != approval["approval_version"]:
            raise provider_controls.ApprovalRejected("Approval changed during evaluation run")
        started = time.monotonic()
        record = {
            "case_id": case["case_id"], "input_sha256": case["input_sha256"],
            **{key: manifest[key] for key in (
                "model", "region", "prompt_version", "schema_version",
                "approval_version", "fixture_sha256"
            )},
        }
        try:
            output, usage = worker._generate(client, case["context"], model)
            if usage["approval_version"] != approval["approval_version"]:
                raise provider_controls.ApprovalRejected("Approval changed during provider call")
            record.update({"output": output, "usage": usage})
        except Exception as exc:
            record["error_type"] = type(exc).__name__
        record["latency_ms"] = int((time.monotonic() - started) * 1000)
        outputs.append(record)
    return manifest, outputs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--outputs", type=Path, required=True)
    parser.add_argument("--run-manifest", type=Path, required=True)
    parser.add_argument("--execute", action="store_true", help="Authorize real provider calls for approved inputs")
    parser.add_argument("--max-calls", type=int, default=10,
                        help="Hard per-run call ceiling; default 10")
    args = parser.parse_args()
    if not args.execute:
        raise SystemExit("No provider calls made. Review cases and pass --execute in an approved environment.")
    if args.outputs.exists() or args.run_manifest.exists():
        raise SystemExit("Refusing to overwrite an existing evaluation record")
    cases = read_jsonl(args.cases)
    validate_cases(cases)
    eligible_count = sum(case.get("eligible") is True for case in cases)
    if args.max_calls < 1 or eligible_count > args.max_calls:
        raise SystemExit(f"Run has {eligible_count} eligible cases; --max-calls must cover them explicitly")
    if any(case["dataset"] == "historical" for case in cases):
        if any(path.resolve().is_relative_to(ROOT) for path in (args.outputs, args.run_manifest)):
            raise SystemExit("Historical output and run manifest must remain outside Git workspace")
    model = config.get_genai_model()
    approval = provider_controls.current_approval(
        model=model, prompt=provider_controls.PROMPT_PREFIX,
    )
    client = worker._get_client()
    if client is None:
        raise SystemExit("Worker provider or privacy gate is disabled")
    manifest, outputs = run(cases, client, approval, model)
    args.outputs.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in outputs), encoding="utf-8")
    args.run_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(cases), "outputs": sum("output" in row for row in outputs),
                      "errors": sum("error_type" in row for row in outputs)}))


if __name__ == "__main__":
    main()
