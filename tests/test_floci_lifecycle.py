"""Opt-in, 100-user Floci failure and publication-fencing acceptance test."""

import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from uuid import uuid4

import pytest

from benchmarks.floci_fixture import make_manifest, verify_floci
from benchmarks.floci_fault_proxy import fault_proxy
from common import aws_clients, evidence, repo
from common.db import db
from lambdas.generate_reviews.handler import generate_campaign
from lambdas.identity_discovery import handler as discovery
from lambdas.risk_evaluation.handler import evaluate_risk
from scripts import migrate
from botocore.config import Config as BotoConfig


@contextmanager
def _isolated_database(backend, tmp_path):
    if backend == "sqlite":
        yield f"sqlite:///{tmp_path / 'lifecycle.db'}"
        return
    admin_url = os.getenv("POSTGRES_TEST_URL")
    if not admin_url:
        pytest.skip("POSTGRES_TEST_URL is required for PostgreSQL lifecycle acceptance")
    psycopg2 = pytest.importorskip("psycopg2")
    from psycopg2 import sql

    schema = "floci_lifecycle_" + uuid4().hex
    admin = psycopg2.connect(admin_url)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    parsed = urlsplit(admin_url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("options", f"-c search_path={schema}"))
    try:
        yield urlunsplit(parsed._replace(query=urlencode(query, quote_via=quote)))
    finally:
        with admin.cursor() as cur:
            cur.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        admin.close()


def _assert_publication(snapshot_id, review_count, *, eligible):
    with db.get_connection() as conn:
        account = "111111111111"
        scope = evidence.IAM_USER_POLICY_SCOPE
        assert repo.published_snapshot(conn, account, scope)[0] == snapshot_id
        current = repo.eligible_published_snapshot(conn, account, scope)
        assert (current is not None) is eligible
        cur = conn.cursor()
        db.execute(cur, "SELECT COUNT(*) FROM access_reviews", ())
        assert cur.fetchone()[0] == review_count
        db.execute(cur, "SELECT COUNT(*) FROM grant_observations WHERE snapshot_id=?", (snapshot_id,))
        assert cur.fetchone()[0] == 357


@pytest.mark.skipif(os.getenv("FLOCI_LIFECYCLE") != "1", reason="requires disposable seeded Floci")
@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
def test_floci_interruption_recovery_and_overlapping_scans(backend, tmp_path, monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.setenv("AWS_ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("FLOCI_ACCOUNT_ID", "111111111111")
    aws_clients.assert_floci_ready()
    manifest = make_manifest("baseline", 42)
    verify_floci(manifest)
    with _isolated_database(backend, tmp_path) as url:
        monkeypatch.setenv("DB_URL", url)
        migrate.apply_sqlite() if backend == "sqlite" else migrate.apply_postgres()

        initial = discovery.discover_identities(None, None)
        assert initial["status"] == "complete"
        assert evaluate_risk(None, None)["grant_observations_assessed"] == 357
        campaign = generate_campaign({"account_id": manifest["account_id"]}, None)
        assert campaign["reviews_created"] == 357
        original = discovery._iter_identities

        def interrupted_page():
            for index, identity in enumerate(original()):
                if index == 1:
                    raise TimeoutError("injected page failure")
                yield identity

        with monkeypatch.context() as patch:
            patch.setattr(discovery, "_iter_identities", interrupted_page)
            failed = discovery.discover_identities(None, None)
        assert failed["status"] == "failed"
        _assert_publication(initial["run_id"], 357, eligible=False)
        with db.get_connection() as conn:
            assert repo.discovery_attempt_outcome(conn, failed["run_id"]) == {
                "collection": "FAILED", "publication": "NOT_PUBLISHED",
            }
        assert generate_campaign({"account_id": manifest["account_id"]}, None) == {
            "status": "blocked", "reason": "no_eligible_published_snapshot",
        }

        def failed_validation(*args, **kwargs):
            raise RuntimeError("injected validation failure")

        with monkeypatch.context() as patch:
            patch.setattr(repo, "record_collection_success", failed_validation)
            rejected = discovery.discover_identities(None, None)
        assert rejected["status"] == "failed"
        _assert_publication(initial["run_id"], 357, eligible=False)

        original_insert = repo.insert_role
        insert_count = 0

        def failed_publication(*args, **kwargs):
            nonlocal insert_count
            insert_count += 1
            if insert_count == 2:
                raise RuntimeError("injected publication failure")
            return original_insert(*args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(repo, "insert_role", failed_publication)
            publication_failed = discovery.discover_identities(None, None)
        assert publication_failed["status"] == "failed"
        _assert_publication(initial["run_id"], 357, eligible=False)
        with db.get_connection() as conn:
            assert repo.discovery_attempt_outcome(conn, publication_failed["run_id"]) == {
                "collection": "SUCCEEDED", "publication": "REJECTED",
            }
            cur = conn.cursor()
            db.execute(cur, "SELECT COUNT(*) FROM published_snapshots WHERE snapshot_id=?", (publication_failed["run_id"],))
            assert cur.fetchone()[0] == 0

        recovered = discovery.discover_identities(None, None)
        assert recovered["status"] == "complete"
        _assert_publication(recovered["run_id"], 357, eligible=True)

        entered = threading.Event()
        release = threading.Event()

        def pause_older():
            for index, identity in enumerate(original()):
                if threading.current_thread().name.startswith("older") and index == 0:
                    entered.set()
                    if not release.wait(120):
                        raise TimeoutError("overlap barrier timed out")
                yield identity

        with monkeypatch.context() as patch:
            patch.setattr(discovery, "_iter_identities", pause_older)
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="older") as pool:
                older_future = pool.submit(discovery.discover_identities, None, None)
                try:
                    assert entered.wait(30), "older scan did not start collection"
                    newer = discovery.discover_identities(None, None)
                    assert newer["status"] == "complete"
                finally:
                    release.set()
                older = older_future.result(timeout=120)
        assert older["status"] == "incomplete"
        _assert_publication(newer["run_id"], 357, eligible=True)
        with db.get_connection() as conn:
            assert repo.source_attempt_head(conn, manifest["account_id"], manifest["source_scope"]) == newer["run_id"]
            assert repo.discovery_attempt_outcome(conn, older["run_id"]) == {
                "collection": "SUCCEEDED", "publication": "SUPERSEDED_BEFORE_PUBLICATION",
            }
            assert repo.discovery_attempt_outcome(conn, newer["run_id"]) == {
                "collection": "SUCCEEDED", "publication": "CURRENT_PUBLISHED",
            }

        # A post-commit audit failure must not turn a published scan into a failure.
        def failed_audit(*args, **kwargs):
            raise RuntimeError("injected post-publication audit failure")

        with monkeypatch.context() as patch:
            patch.setattr(repo, "insert_audit_log", failed_audit)
            post_commit = discovery.discover_identities(None, None)
        assert post_commit["status"] == "complete"
        _assert_publication(post_commit["run_id"], 357, eligible=True)

        # The newer scan fails while the older one is paused. The older scan
        # still cannot publish because a later attempt already owns the head.
        entered.clear()
        release.clear()
        with monkeypatch.context() as patch:
            patch.setattr(discovery, "_iter_identities", pause_older)
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="older") as pool:
                older_future = pool.submit(discovery.discover_identities, None, None)
                try:
                    assert entered.wait(30), "older scan did not start collection"

                    def newer_fails():
                        for index, identity in enumerate(original()):
                            if index == 1:
                                raise TimeoutError("injected newer attempt failure")
                            yield identity

                    patch.setattr(discovery, "_iter_identities", newer_fails)
                    failed_newer = discovery.discover_identities(None, None)
                    assert failed_newer["status"] == "failed"
                finally:
                    release.set()
                stale_older = older_future.result(timeout=120)
        assert stale_older["status"] == "incomplete"
        _assert_publication(post_commit["run_id"], 357, eligible=False)
        with db.get_connection() as conn:
            assert repo.discovery_attempt_outcome(conn, stale_older["run_id"]) == {
                "collection": "SUCCEEDED", "publication": "SUPERSEDED_BEFORE_PUBLICATION",
            }
            assert repo.discovery_attempt_outcome(conn, failed_newer["run_id"]) == {
                "collection": "FAILED", "publication": "NOT_PUBLISHED",
            }

        final_recovery = discovery.discover_identities(None, None)
        assert final_recovery["status"] == "complete"
        _assert_publication(final_recovery["run_id"], 357, eligible=True)


@pytest.mark.skipif(os.getenv("FLOCI_CRASH") != "1", reason="requires disposable seeded Floci")
@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
def test_floci_process_termination_boundaries(backend, tmp_path, monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.setenv("AWS_ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("FLOCI_ACCOUNT_ID", "111111111111")
    aws_clients.assert_floci_ready()
    manifest = make_manifest("baseline", 42)
    verify_floci(manifest)
    with _isolated_database(backend, tmp_path) as url:
        monkeypatch.setenv("DB_URL", url)
        migrate.apply_sqlite() if backend == "sqlite" else migrate.apply_postgres()
        initial = discovery.discover_identities(None, None)
        assert initial["status"] == "complete"
        assert evaluate_risk(None, None)["grant_observations_assessed"] == 357
        campaign = generate_campaign({"account_id": manifest["account_id"]}, None)
        assert campaign["reviews_created"] == 357
        current = initial["run_id"]

        for boundary in ("before_publication", "during_publication", "after_commit"):
            child = subprocess.run(
                [sys.executable, "-m", "benchmarks.floci_crash_worker", boundary],
                env=os.environ.copy(), capture_output=True, text=True, timeout=120,
            )
            assert child.returncode == 73, (boundary, child.stdout, child.stderr)
            with db.get_connection() as conn:
                attempted = repo.source_attempt_head(
                    conn, manifest["account_id"], manifest["source_scope"]
                )
                assert attempted != current
                cur = conn.cursor()
                db.execute(cur, "SELECT status FROM discovery_runs WHERE run_id=?", (attempted,))
                assert cur.fetchone() == (("COMPLETE",) if boundary == "after_commit" else ("RUNNING",))
                assert repo.collection_succeeded(conn, attempted)
                db.execute(cur, "SELECT COUNT(*) FROM published_snapshots WHERE snapshot_id=?", (attempted,))
                assert cur.fetchone()[0] == (1 if boundary == "after_commit" else 0)
                db.execute(cur, """SELECT COUNT(*) FROM audit_logs
                    WHERE entity_type='discovery_run' AND entity_id=?""", (attempted,))
                assert cur.fetchone()[0] == 0
                assert repo.published_snapshot(conn, manifest["account_id"], manifest["source_scope"])[0] == (
                    attempted if boundary == "after_commit" else current
                )
            _assert_publication(
                attempted if boundary == "after_commit" else current,
                357, eligible=boundary == "after_commit",
            )
            recovered = discovery.discover_identities(None, None)
            assert recovered["status"] == "complete"
            current = recovered["run_id"]
            _assert_publication(current, 357, eligible=True)
            if boundary != "after_commit":
                with db.get_connection() as conn:
                    assert repo.discovery_attempt_outcome(conn, attempted) == {
                        "collection": "SUCCEEDED",
                        "publication": "SUPERSEDED_BEFORE_PUBLICATION",
                    }


@pytest.mark.skipif(os.getenv("FLOCI_FAULTS") != "1", reason="requires disposable seeded Floci")
@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
def test_floci_http_faults_keep_partial_scans_unpublished(backend, tmp_path, monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.setenv("AWS_ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("FLOCI_ACCOUNT_ID", "111111111111")
    aws_clients.assert_floci_ready()
    manifest = make_manifest("baseline", 42)
    verify_floci(manifest)
    with _isolated_database(backend, tmp_path) as url:
        monkeypatch.setenv("DB_URL", url)
        migrate.apply_sqlite() if backend == "sqlite" else migrate.apply_postgres()
        initial = discovery.discover_identities(None, None)
        assert initial["status"] == "complete"
        initial_id = initial["run_id"]
        original_iam_client = discovery._iam_client

        def short_timeout_client():
            return aws_clients.client("iam", client_config=BotoConfig(
                connect_timeout=1, read_timeout=0.1,
                retries={"mode": "standard", "max_attempts": 1},
            ))

        for mode in ("throttle", "timeout", "malformed_xml", "missing_marker"):
            with fault_proxy(mode) as endpoint, monkeypatch.context() as patch:
                patch.setenv("FLOCI_ENDPOINT_URL", endpoint)
                patch.setattr(discovery, "_iam_client", short_timeout_client)
                failed = discovery.discover_identities(None, None)
            assert failed["status"] == "failed", (mode, failed)
            _assert_publication(initial_id, 0, eligible=False)
            with db.get_connection() as conn:
                assert repo.discovery_attempt_outcome(conn, failed["run_id"]) == {
                    "collection": "FAILED", "publication": "NOT_PUBLISHED",
                }

        assert discovery._iam_client is original_iam_client
        recovered = discovery.discover_identities(None, None)
        assert recovered["status"] == "complete"
        _assert_publication(recovered["run_id"], 0, eligible=True)
