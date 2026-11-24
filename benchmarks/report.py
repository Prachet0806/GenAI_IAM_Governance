"""Aggregate comparable Floci benchmark runs into JSON and Markdown."""

import argparse
import json
import statistics
from pathlib import Path


def summarize(paths: list[Path]) -> dict:
    results = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    if len(results) < 3 or not all(r.get("schema_version") == "floci-benchmark-result-v1" and r.get("pass") for r in results):
        raise ValueError("Provide at least three successful benchmark result files")
    invariant = ("profile", "seed", "account_id", "commit", "workspace_sha256",
                 "manifest_sha256", "floci_version", "floci_image_digest", "expected_counts")
    for key in invariant:
        if any(r.get(key) != results[0].get(key) for r in results[1:]):
            raise ValueError(f"Results are not comparable: {key} differs")
    if any(r["actual"]["risk_distribution"] != results[0]["actual"]["risk_distribution"] for r in results[1:]):
        raise ValueError("Risk distribution differs between runs")
    summary = {"schema_version": "floci-benchmark-summary-v1", "runs": len(results),
               "profile": results[0]["profile"], "seed": results[0]["seed"],
               "commit": results[0]["commit"], "workspace_sha256": results[0].get("workspace_sha256"),
               "manifest_sha256": results[0].get("manifest_sha256"),
               "floci_version": results[0]["floci_version"],
               "floci_image_digest": results[0].get("floci_image_digest"),
               "working_tree_clean": results[0].get("working_tree_clean", False),
               "expected_counts": results[0]["expected_counts"],
               "risk_distribution": results[0]["actual"]["risk_distribution"],
               "backends": {}}
    for backend in sorted({r["db_backend"] for r in results}):
        subset = [r for r in results if r["db_backend"] == backend]
        if len(subset) < 3:
            raise ValueError(f"Need three runs for {backend}")
        stages = subset[0]["durations_seconds"]
        summary["backends"][backend] = {
            "runs": len(subset),
            "durations_seconds": {stage: {
                "median": statistics.median(r["durations_seconds"][stage] for r in subset),
                "max": max(r["durations_seconds"][stage] for r in subset),
            } for stage in stages},
            "peak_rss_bytes": {"median": statistics.median(r["peak_rss_bytes"] for r in subset),
                               "max": max(r["peak_rss_bytes"] for r in subset)},
            "database_bytes": {"median": statistics.median(r["database_bytes"] for r in subset),
                               "max": max(r["database_bytes"] for r in subset)},
            "sdk_calls": subset[0].get("sdk", {}).get("calls", {}),
            "http_failures": sum(r.get("sdk", {}).get("http_failures", 0) for r in subset),
        }
    return summary


def markdown(summary: dict) -> str:
    lines = [f"# Floci {summary['profile']} benchmark", "",
             f"Seed: {summary['seed']} · Floci: {summary['floci_version']} · commit: `{summary['commit']}`", "",
             f"Working tree clean: {summary['working_tree_clean']} · source fingerprint: `{summary['workspace_sha256']}`", "",
             f"Fixture: {summary['expected_counts']['users']} users, {summary['expected_counts']['groups']} groups, "
             f"{summary['expected_counts']['grant_paths']} grant paths and reviews.", "",
             "| Backend | Runs | Discovery median / max (s) | Risk median / max (s) | Campaign median / max (s) | Peak RSS max (MiB) | DB size max (MiB) |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for backend, data in summary["backends"].items():
        def pair(stage):
            item = data["durations_seconds"][stage]
            return f"{item['median']:.2f} / {item['max']:.2f}"
        lines.append(f"| {backend} | {data['runs']} | {pair('discovery')} | {pair('risk')} | {pair('campaign')} | "
                     f"{data['peak_rss_bytes']['max']/1048576:.1f} | {data['database_bytes']['max']/1048576:.1f} |")
    lines.extend(["", "All runs matched the deterministic grant manifest, had complete policy evidence, "
                  "and created one review per assessed grant. This local emulator result does not qualify AWS latency, "
                  "throttling, effective permissions or authorization.", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, nargs="+")
    parser.add_argument("--output-prefix", type=Path, required=True)
    args = parser.parse_args()
    summary = summarize(args.results)
    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    args.output_prefix.with_suffix(".json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_prefix.with_suffix(".md").write_text(markdown(summary), encoding="utf-8")
    print(args.output_prefix.with_suffix(".md"))


if __name__ == "__main__":
    main()
