"""Seed a disposable Floci account from a deterministic benchmark profile."""

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.floci_fixture import make_manifest, seed_floci, verify_floci


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="baseline")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metrics-output", type=Path)
    args = parser.parse_args()
    manifest = make_manifest(args.profile, args.seed)
    start = time.perf_counter()
    seeded = seed_floci(manifest)
    seed_seconds = time.perf_counter() - start
    verified = verify_floci(manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = {"manifest": str(args.output), "seed_seconds": seed_seconds,
              "writes": seeded["writes"], "verified_counts": verified}
    if args.metrics_output:
        args.metrics_output.parent.mkdir(parents=True, exist_ok=True)
        args.metrics_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
