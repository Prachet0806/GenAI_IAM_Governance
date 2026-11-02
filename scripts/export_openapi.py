"""Export the FastAPI OpenAPI schema for the generated frontend client."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.review_service import app


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    document = json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"
    if args.check:
        try:
            existing = args.check.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"OpenAPI schema is unavailable: {exc}", file=sys.stderr)
            return 1
        if existing != document:
            print("OpenAPI schema is stale; run scripts/export_openapi.py --output <path>", file=sys.stderr)
            return 1
        return 0
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(document, encoding="utf-8")
    else:
        sys.stdout.write(document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
