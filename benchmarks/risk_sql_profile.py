"""Diagnostic-only client SQL timings plus PostgreSQL server-side statistics."""

import re
import statistics
import time
from collections import defaultdict
from contextlib import contextmanager

from common import config
from common.db import db


def _normalized(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


def _p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    return ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)]


def _prepare_pg_statistics():
    if config.db_is_sqlite():
        return
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
        cur.execute("SELECT pg_stat_statements_reset()")
        cur.fetchone()


def _pg_statistics() -> dict | None:
    if config.db_is_sqlite():
        return None
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """SELECT query,calls,rows,total_plan_time,total_exec_time
               FROM pg_stat_statements
               WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database())
                 AND userid=(SELECT usesysid FROM pg_user WHERE usename=current_user)
               ORDER BY total_plan_time+total_exec_time DESC"""
        )
        rows = cur.fetchall()
    statements = [
        {"sql": _normalized(row[0]), "calls": int(row[1]),
         "rows_reported": int(row[2]), "planning_seconds": float(row[3]) / 1000,
         "execution_seconds": float(row[4]) / 1000}
        for row in rows if row[0] and not row[0].startswith("SELECT pg_stat_statements_reset")
    ]
    return {
        "planning_seconds": sum(row["planning_seconds"] for row in statements),
        "execution_seconds": sum(row["execution_seconds"] for row in statements),
        "top_five": statements[:5],
        "statement_count": sum(row["calls"] for row in statements),
    }


def profile_risk_stage(fn):
    """Run one risk stage with reversible instrumentation; do not include setup."""
    _prepare_pg_statistics()
    timings = defaultdict(list)
    rowcounts = defaultdict(int)
    unknown_rowcount = set()
    transaction_seconds = []
    original_execute = db.execute
    original_connection = db.get_connection

    def measured_execute(cursor, sql, params=()):
        key = _normalized(sql)
        started = time.perf_counter()
        try:
            return original_execute(cursor, sql, params)
        finally:
            timings[key].append(time.perf_counter() - started)
            rows = getattr(cursor, "rowcount", -1)
            if rows < 0:
                unknown_rowcount.add(key)
            else:
                rowcounts[key] += rows

    @contextmanager
    def measured_connection():
        with original_connection() as conn:
            started = time.perf_counter()
            try:
                yield conn
            finally:
                # The timer also includes commit/rollback on leaving the context.
                pass
        transaction_seconds.append(time.perf_counter() - started)

    db.execute = measured_execute
    db.get_connection = measured_connection
    started = time.perf_counter()
    try:
        result = fn()
    finally:
        wall = time.perf_counter() - started
        db.execute = original_execute
        db.get_connection = original_connection
    groups = [
        {"sql": sql, "count": len(samples), "total_client_seconds": sum(samples),
         "average_client_ms": statistics.mean(samples) * 1000,
         "p95_client_ms": _p95(samples) * 1000,
         "driver_rowcount_sum": None if sql in unknown_rowcount else rowcounts[sql]}
        for sql, samples in timings.items()
    ]
    groups.sort(key=lambda row: row["total_client_seconds"], reverse=True)
    client_sql = sum(row["total_client_seconds"] for row in groups)
    return result, {
        "schema_version": "risk-sql-profile-v1",
        "statement_count": sum(row["count"] for row in groups),
        "client_sql_seconds": client_sql,
        "stage_wall_seconds": wall,
        "non_sql_client_seconds": max(0, wall - client_sql),
        "transaction_count": len(transaction_seconds),
        "transaction_seconds": sum(transaction_seconds),
        "statements": groups,
        "server": _pg_statistics(),
        "timing_note": "Client SQL includes driver adaptation, network round trip, and server work; server planning/execution excludes network and client work. Their difference is not a pure network measurement.",
    }
