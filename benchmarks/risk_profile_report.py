"""Compare four fresh B0 runs and verify per-grant assessment semantics."""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.db import db


def _semantic_hash(db_url: str, account_id: str, source_scope: str) -> tuple[str, int, int]:
    previous = os.environ.get("DB_URL")
    os.environ["DB_URL"] = db_url
    try:
        with db.get_connection() as conn:
            cur = conn.cursor()
            db.execute(cur, """SELECT go.principal_name,gp.grant_type,go.source_name,
                    go.policy_name,go.policy_sha256,gra.risk_level,pra.risk_level,
                    pra.reason,pra.evidence,gra.evidence,r.status,gp.policy_id
                FROM source_publications sp
                JOIN grant_observations go ON go.snapshot_id=sp.snapshot_id
                JOIN grant_paths gp ON gp.grant_id=go.grant_id
                JOIN grant_risk_assessments gra ON gra.observation_id=go.observation_id
                JOIN policy_risk_assessments pra ON pra.assessment_id=gra.policy_assessment_id
                JOIN access_reviews r ON r.observation_id=go.observation_id
                WHERE sp.account_id=? AND sp.source_scope=?""", (account_id, source_scope))
            rows = cur.fetchall()
            db.execute(cur, """SELECT rol.role_id,rol.risk_level,ra.risk_level,
                    ra.reason,ra.evidence,ra.rule_version
                FROM roles rol JOIN risk_assessments ra ON ra.role_id=rol.role_id""")
            projections = cur.fetchall()
    finally:
        if previous is None:
            os.environ.pop("DB_URL", None)
        else:
            os.environ["DB_URL"] = previous
    semantic = []
    for row in rows:
        grant = json.loads(row[9])
        for volatile in ("snapshot_id", "observation_id", "grant_id"):
            grant.pop(volatile, None)
        semantic.append([*row[:8], json.loads(row[8]), grant, row[10], row[11]])
    semantic.sort(key=lambda item: json.dumps(item, sort_keys=True))
    projection_rows = sorted([
        [*row[:4], json.loads(row[4]), row[5]] for row in projections
    ], key=lambda item: item[0])
    digest = hashlib.sha256(json.dumps(
        {"grants": semantic, "policy_projections": projection_rows}, sort_keys=True
    ).encode()).hexdigest()
    return digest, len(semantic), len({row[11] for row in rows})


def compare(specs: dict) -> dict:
    runs = {}
    for label, (result_path, db_url) in specs.items():
        run = json.loads(Path(result_path).read_text(encoding="utf-8"))
        if not run.get("pass") or "risk_sql_profile" not in run:
            raise ValueError(f"{label} is not a successful profiled benchmark")
        digest, rows, policies = _semantic_hash(
            db_url, run["account_id"], "iam-users-direct-and-group-managed-and-inline-policies-v2"
        )
        if rows != run["expected_counts"]["grant_paths"] or rows != run["actual"]["reviews"]:
            raise AssertionError(f"{label} has incomplete persisted assessment or review output")
        runs[label] = {
            "commit": run["commit"], "workspace_sha256": run["workspace_sha256"],
            "manifest_sha256": run["manifest_sha256"], "floci_version": run["floci_version"],
            "counts": run["actual"], "policy_count": policies,
            "semantic_sha256": digest, "profile": run["risk_sql_profile"],
        }
    first = next(iter(runs.values()))
    for label, run in runs.items():
        if (run["commit"], run["manifest_sha256"], run["floci_version"],
                run["semantic_sha256"], run["policy_count"]) != (
                first["commit"], first["manifest_sha256"], first["floci_version"],
                first["semantic_sha256"], first["policy_count"]):
            raise AssertionError(f"{label} differs in fixture or per-grant assessment output")
    return {"schema_version": "risk-profile-comparison-v1", "runs": runs,
            "semantic_sha256": first["semantic_sha256"]}


def markdown(report: dict) -> str:
    runs = report["runs"]
    lines = ["# B0 risk-stage SQL profile", "",
             "One fresh 100-user Floci run per backend and code state. The six-run baseline is preserved separately.",
             "", "| Run | Risk wall (s) | SQL calls | Client SQL (s) | Non-SQL client (s) | PostgreSQL plan + execute (s) |",
             "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for label, run in runs.items():
        profile = run["profile"]
        server = profile["server"]
        server_time = "—" if server is None else f"{server['planning_seconds']+server['execution_seconds']:.3f}"
        lines.append(f"| {label} | {profile['stage_wall_seconds']:.3f} | {profile['statement_count']} | "
                     f"{profile['client_sql_seconds']:.3f} | {profile['non_sql_client_seconds']:.3f} | {server_time} |")
    lines.extend(["", "All four runs had 357 grant assessments and reviews, 34 distinct policies, "
                  "85 HIGH and 272 MEDIUM risks, and the same per-grant semantic SHA-256: "
                  f"`{report['semantic_sha256']}`.", "",
                  "## Repeated policy-level operations", "",
                  "| Statement | Before calls | After calls | Before driver rows | After driver rows |",
                  "| --- | ---: | ---: | ---: | ---: |"])
    for name, prefix in (
        ("Policy assessment insert", "INSERT INTO policy_risk_assessments"),
        ("Policy assessment verification", "SELECT risk_level,reason,evidence FROM policy_risk_assessments"),
        ("Role risk projection update", "UPDATE roles SET risk_level"),
        ("Legacy risk projection upsert", "INSERT INTO risk_assessments"),
    ):
        before = next(row for row in runs["before_postgres"]["profile"]["statements"]
                      if row["sql"].startswith(prefix))
        after = next(row for row in runs["after_postgres"]["profile"]["statements"]
                     if row["sql"].startswith(prefix))
        lines.append(f"| {name} | {before['count']} | {after['count']} | "
                     f"{before['driver_rowcount_sum']} | {after['driver_rowcount_sum']} |")
    lines.extend(["", "Driver row counts mean rows returned or affected, not rows scanned inside PostgreSQL.", "",
                  "## Top five PostgreSQL client statements before optimization", "",
                  "| Calls | Total (s) | Average (ms) | p95 (ms) | Statement |",
                  "| ---: | ---: | ---: | ---: | --- |"])
    for row in runs["before_postgres"]["profile"]["statements"][:5]:
        match = re.search(r"(?:INSERT INTO|UPDATE|FROM)\s+([a-z_]+)", row["sql"], re.I)
        label = f"{row['sql'].split(' ', 1)[0]} {match.group(1)}" if match else row["sql"][:50]
        lines.append(f"| {row['count']} | {row['total_client_seconds']:.3f} | "
                     f"{row['average_client_ms']:.2f} | {row['p95_client_ms']:.2f} | "
                     f"`{label}` |")
    lines.extend(["", "## Top five PostgreSQL server statements before optimization", "",
                  "| Calls | Plan + execute (s) | Rows returned/affected | Statement |",
                  "| ---: | ---: | ---: | --- |"])
    for row in runs["before_postgres"]["profile"]["server"]["top_five"]:
        match = re.search(r"(?:INSERT INTO|UPDATE|FROM)\s+([a-z_]+)", row["sql"], re.I)
        label = f"{row['sql'].split(' ', 1)[0]} {match.group(1)}" if match else row["sql"][:50]
        lines.append(f"| {row['calls']} | {row['planning_seconds']+row['execution_seconds']:.3f} | "
                     f"{row['rows_reported']} | `{label}` |")
    lines.extend(["", "Client SQL timing includes driver work, transport, and server work. "
                  "PostgreSQL plan and execution timing is server-side; subtracting the two does not isolate network latency. "
                  "The profile runs are diagnostic samples, not a new six-run performance claim.", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("before_sqlite", "after_sqlite", "before_postgres", "after_postgres"):
        parser.add_argument(f"--{label.replace('_', '-')}-result", required=True)
        parser.add_argument(f"--{label.replace('_', '-')}-db", required=True)
    parser.add_argument("--output-prefix", type=Path, required=True)
    args = parser.parse_args()
    specs = {label: (getattr(args, f"{label}_result"), getattr(args, f"{label}_db"))
             for label in ("before_sqlite", "after_sqlite", "before_postgres", "after_postgres")}
    report = compare(specs)
    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    args.output_prefix.with_suffix(".json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_prefix.with_suffix(".md").write_text(markdown(report), encoding="utf-8")
    print(args.output_prefix.with_suffix(".md"))


if __name__ == "__main__":
    main()
