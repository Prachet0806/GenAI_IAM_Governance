"""Regression coverage for export integrity and operations history."""

import pytest

from api import review_service
from common import repo
from common.db import db
from reports import export_audit
from tests.test_campaign_workflow import _setup


def test_export_does_not_report_success_without_its_audit_index(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LOCAL_ONLY", "true")

    def fail_audit_record(*_args, **_kwargs):
        raise RuntimeError("audit index unavailable")

    monkeypatch.setattr(repo, "insert_audit_log", fail_audit_record)
    with pytest.raises(RuntimeError, match="audit index unavailable"):
        export_audit.export_audit_report()


@pytest.mark.parametrize("value,expected", [
    ("=HYPERLINK(\"https://example.test\")", "'=HYPERLINK(\"https://example.test\")"),
    ("  +SUM(1,2)", "'  +SUM(1,2)"),
    ("plain text", "plain text"),
    (None, None),
])
def test_csv_values_are_safe_for_spreadsheets(value, expected):
    assert export_audit._spreadsheet_safe(value) == expected


def test_operations_jobs_pages_historical_discovery_runs(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setenv("OIDC_ACCOUNT_SCOPE_CLAIM", "account_scopes")
    monkeypatch.setenv("REMEDIATION_OPERATOR_GROUP", "operators")
    with db.get_connection() as conn:
        conn.executemany(
            """INSERT INTO discovery_runs
            (run_id,started_at,status,source,account_id,source_scope)
            VALUES (?,?,'COMPLETE','AWS:iam-users','123456789012','iam-users')""",
            [(f"job-{index:04d}", f"2026-11-01T00:{index // 60:02d}:{index % 60:02d}+00:00")
             for index in range(1002)],
        )
        conn.execute("""INSERT INTO discovery_runs
            (run_id,started_at,status,source,account_id,source_scope)
            VALUES ('other-account','2026-11-02T00:00:00+00:00','COMPLETE',
                    'AWS:iam-users','999999999999','iam-users')""")
    result = review_service.operations_jobs(
        limit=5, offset=1000,
        claims={"sub": "operator", "groups": ["operators"],
                "account_scopes": ["123456789012"]},
    )
    assert result["total"] == 1002
    assert len(result["jobs"]) == 2
    assert all(job["account_id"] == "123456789012" for job in result["jobs"])
    assert result["has_more"] is False
