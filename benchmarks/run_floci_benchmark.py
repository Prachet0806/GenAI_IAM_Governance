"""Run the real IAM user discovery, risk and campaign pipeline on a fresh DB."""

import argparse
import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.floci_fixture import make_manifest, verify_floci
from benchmarks.risk_sql_profile import profile_risk_stage
from common import aws_clients, config, evidence, repo
from common.db import db
from lambdas.generate_reviews.handler import generate_campaign
from lambdas.identity_discovery.handler import discover_identities
from lambdas.risk_evaluation.handler import evaluate_risk
from scripts import migrate


def _peak_rss_bytes() -> int | None:
    if os.name == "nt":
        class Counters(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong)] + [
                (name, ctypes.c_size_t) for name in (
                    "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                    "PagefileUsage", "PeakPagefileUsage",
                )
            ]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
        psapi.GetProcessMemoryInfo.restype = ctypes.c_bool
        if psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            return int(counters.PeakWorkingSetSize)
        return None
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak * (1024 if sys.platform.startswith("linux") else 1))


def _git(args: list[str]) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def _workspace_sha256() -> str:
    digest = hashlib.sha256()
    diff = subprocess.run(["git", "diff", "HEAD", "--binary"], cwd=ROOT,
                          capture_output=True, check=True)
    digest.update(diff.stdout)
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, capture_output=True, check=True,
    )
    for relative in sorted(path for path in untracked.stdout.split(b"\0") if path):
        digest.update(relative)
        digest.update((ROOT / os.fsdecode(relative)).read_bytes())
    return digest.hexdigest()


def _fresh_db(url: str) -> None:
    if config.db_is_sqlite(url):
        path = Path(config.get_sqlite_path(url))
        if path.exists():
            raise RuntimeError(f"Benchmark DB already exists: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        return
    if not url.startswith(("postgresql://", "postgres://")):
        raise ValueError("Only SQLite and PostgreSQL benchmark databases are supported")
    import psycopg2
    with psycopg2.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM pg_tables WHERE schemaname='public'")
            if cur.fetchone()[0]:
                raise RuntimeError("PostgreSQL benchmark database is not empty")


def _database_size(url: str) -> int:
    if config.db_is_sqlite(url):
        return Path(config.get_sqlite_path(url)).stat().st_size
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT pg_database_size(current_database())")
        return int(cur.fetchone()[0])


def _database_assertions(manifest: dict, snapshot_id: str, campaign_id: str) -> dict:
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(cur, "SELECT source,status FROM discovery_runs WHERE run_id=?", (snapshot_id,))
        if cur.fetchone() != (f"FLOCI:{manifest['source_scope']}", "COMPLETE"):
            raise AssertionError("Discovery source or status differs from Floci fixture")
        if repo.source_attempt_head(conn, manifest["account_id"], manifest["source_scope"]) != snapshot_id:
            raise AssertionError("The published scan is not the current source head")
        db.execute(cur, """SELECT o.principal_name,p.grant_type,o.source_name,o.policy_name
            FROM grant_observations o JOIN grant_paths p ON p.grant_id=o.grant_id
            WHERE o.snapshot_id=?""", (snapshot_id,))
        actual = sorted(tuple(row) for row in cur.fetchall())
        expected = sorted(tuple(row) for row in manifest["expected_grants"])
        if actual != expected:
            missing = sorted(set(expected) - set(actual))[:5]
            extra = sorted(set(actual) - set(expected))[:5]
            raise AssertionError(f"Grant mismatch: expected {len(expected)}, actual {len(actual)}, missing={missing}, extra={extra}")
        db.execute(cur, "SELECT COUNT(*) FROM grant_observations WHERE snapshot_id=? AND evidence_status!='COMPLETE'", (snapshot_id,))
        if cur.fetchone()[0] != 0:
            raise AssertionError("Published snapshot contains missing policy evidence")
        if not repo.snapshot_risk_complete(conn, snapshot_id, evidence.POLICY_RULE_VERSION):
            raise AssertionError("Risk assessment is incomplete")
        db.execute(cur, "SELECT COUNT(*) FROM access_reviews WHERE campaign_id=?", (campaign_id,))
        review_count = cur.fetchone()[0]
        if review_count != manifest["counts"]["grant_paths"]:
            raise AssertionError(f"Review count {review_count} differs from expected grants")
        db.execute(cur, """SELECT gra.risk_level,COUNT(*) FROM grant_risk_assessments gra
            JOIN grant_observations o ON o.observation_id=gra.observation_id
            WHERE o.snapshot_id=? GROUP BY gra.risk_level""", (snapshot_id,))
        risks = {row[0]: row[1] for row in cur.fetchall()}
        if sum(risks.values()) != manifest["counts"]["grant_paths"]:
            raise AssertionError("Risk distribution does not cover every grant")
        return {"grant_paths": len(actual), "reviews": review_count, "risk_distribution": risks}


def run(manifest: dict, db_url: str, image_digest: str | None = None,
        risk_profile: bool = False) -> dict:
    if config.iam_source_mode() != "FLOCI":
        raise RuntimeError("Benchmark requires Floci mode")
    if manifest != make_manifest(manifest["profile"], manifest["seed"]):
        raise ValueError("Manifest differs from deterministic fixture contract")
    _fresh_db(db_url)
    health = aws_clients.assert_floci_ready()
    verify_floci(manifest)
    os.environ["DB_URL"] = db_url
    migrate_start = time.perf_counter()
    migrate.apply_sqlite() if config.db_is_sqlite(db_url) else migrate.apply_postgres()
    migrate_seconds = time.perf_counter() - migrate_start
    instrumentation = {"collection_validation_seconds": 0.0, "publication_seconds": 0.0}
    sdk_metrics = {"calls": {}, "list_pages": {}, "http_failures": 0}
    original_collect = repo.record_collection_success
    original_publish = repo.publish_discovery_snapshot
    original_client = aws_clients.client

    def instrumented_client(service, **kwargs):
        client = original_client(service, **kwargs)

        def before_call(**event):
            name = f"{service}.{event['model'].name}"
            sdk_metrics["calls"][name] = sdk_metrics["calls"].get(name, 0) + 1

        def after_call(**event):
            name = f"{service}.{event['model'].name}"
            if event["model"].name.startswith("List"):
                sdk_metrics["list_pages"][name] = sdk_metrics["list_pages"].get(name, 0) + 1
            if event["http_response"].status_code >= 400:
                sdk_metrics["http_failures"] += 1

        client.meta.events.register(f"before-call.{service}.*", before_call)
        client.meta.events.register(f"after-call.{service}.*", after_call)
        return client

    def timed_collect(*args, **kwargs):
        start = time.perf_counter()
        try:
            return original_collect(*args, **kwargs)
        finally:
            instrumentation["collection_validation_seconds"] += time.perf_counter() - start

    def timed_publish(*args, **kwargs):
        start = time.perf_counter()
        try:
            return original_publish(*args, **kwargs)
        finally:
            instrumentation["publication_seconds"] += time.perf_counter() - start

    repo.record_collection_success = timed_collect
    repo.publish_discovery_snapshot = timed_publish
    aws_clients.client = instrumented_client
    try:
        start = time.perf_counter()
        discovery = discover_identities(None, None)
        discovery_seconds = time.perf_counter() - start
    finally:
        repo.record_collection_success = original_collect
        repo.publish_discovery_snapshot = original_publish
        aws_clients.client = original_client
    if discovery["status"] != "complete" or discovery["users_processed"] != manifest["counts"]["users"]:
        raise AssertionError(f"Discovery incomplete or wrong user count: {discovery}")
    snapshot_id = discovery["run_id"]
    start = time.perf_counter()
    if risk_profile:
        risk, sql_profile = profile_risk_stage(lambda: evaluate_risk(None, None))
    else:
        risk, sql_profile = evaluate_risk(None, None), None
    risk_seconds = (sql_profile["stage_wall_seconds"] if sql_profile
                    else time.perf_counter() - start)
    if risk.get("grant_observations_assessed") != manifest["counts"]["observations"]:
        raise AssertionError(f"Wrong risk assessment count: {risk}")
    start = time.perf_counter()
    campaign = generate_campaign({"account_id": manifest["account_id"],
                                  "source_scope": manifest["source_scope"]}, None)
    campaign_seconds = time.perf_counter() - start
    if campaign.get("reviews_created") != manifest["counts"]["grant_paths"]:
        raise AssertionError(f"Wrong campaign count: {campaign}")
    assertions = _database_assertions(manifest, snapshot_id, campaign["campaign_id"])
    status = _git(["status", "--porcelain"])
    manifest_digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return {
        "schema_version": "floci-benchmark-result-v1", "pass": True,
        "profile": manifest["profile"], "seed": manifest["seed"],
        "account_id": manifest["account_id"], "commit": _git(["rev-parse", "HEAD"]),
        "working_tree_status_sha256": hashlib.sha256(status.encode()).hexdigest(),
        "workspace_sha256": _workspace_sha256(), "manifest_sha256": manifest_digest,
        "working_tree_clean": status == "", "python": platform.python_version(),
        "floci_version": health.get("version"), "db_backend": "sqlite" if config.db_is_sqlite(db_url) else "postgresql",
        "floci_image_digest": image_digest,
        "durations_seconds": {"migration": migrate_seconds, "discovery": discovery_seconds,
                              "collection_validation": instrumentation["collection_validation_seconds"],
                              "publication": instrumentation["publication_seconds"],
                              "risk": risk_seconds, "campaign": campaign_seconds},
        "peak_rss_bytes": _peak_rss_bytes(), "database_bytes": _database_size(db_url),
        "expected_counts": manifest["counts"], "actual": assertions,
        "sdk": sdk_metrics,
        **({"risk_sql_profile": sql_profile} if risk_profile else {}),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--db-url", required=True, help="Fresh, dedicated SQLite or PostgreSQL DB URL")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-digest", help="Digest from docker image inspect")
    parser.add_argument("--profile-risk", action="store_true",
                        help="Record client SQL timings and PostgreSQL server statistics")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    result = run(manifest, args.db_url, args.image_digest, args.profile_risk)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
