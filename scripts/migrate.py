#scripts/migrate.py
import os
import sys
from pathlib import Path

# Ensure repository root is on sys.path for module imports
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, logger

try:
    import sqlite3
except ImportError:  # pragma: no cover
    sqlite3 = None

try:
    import psycopg2  # type: ignore
    import psycopg2.extras  # type: ignore
except ImportError:
    psycopg2 = None  # type: ignore


SQL_DIR = ROOT / "sql"


def load_sql(name: str) -> str:
    path = SQL_DIR / name
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    # Tolerate stray '#' header lines (not valid SQL); treat as comments.
    cleaned = "\n".join(
        line if not line.lstrip().startswith("#") else "-- " + line.lstrip()[1:]
        for line in content.splitlines()
    )
    return cleaned


import re


def _split_statements(sql_blob: str):
    """Split on semicolons outside of quotes, line/block comments, and $$ bodies."""
    stmts = []
    buf: list[str] = []
    i = 0
    n = len(sql_blob)
    in_single = False
    in_double = False
    in_line_comment = False
    in_block_comment = False
    in_dollar = False
    while i < n:
        if in_line_comment:
            buf.append(sql_blob[i])
            if sql_blob[i] == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if sql_blob.startswith("*/", i):
                buf.append("*/")
                i += 2
                in_block_comment = False
            else:
                buf.append(sql_blob[i])
                i += 1
            continue
        if not in_single and not in_double and sql_blob.startswith("--", i):
            in_line_comment = True
            buf.append("--")
            i += 2
            continue
        if not in_single and not in_double and sql_blob.startswith("/*", i):
            in_block_comment = True
            buf.append("/*")
            i += 2
            continue
        if not in_single and not in_double and not in_line_comment and sql_blob.startswith("$$", i):
            in_dollar = not in_dollar
            buf.append("$$")
            i += 2
            continue
        ch = sql_blob[i]
        if ch == "'" and not in_double and not in_dollar:
            if in_single and sql_blob.startswith("''", i):
                buf.append("''")
                i += 2
                continue
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single and not in_dollar:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if ch == ";" and not in_single and not in_double and not in_dollar:
            stmt = "".join(buf).strip()
            if stmt:
                stmts.append(stmt)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        stmts.append(tail)
    return stmts


def _execute_statements(cur, sql_blob: str):
    """
    Execute multiple statements (quote/comment/$$ aware splitter).
    """
    for stmt in _split_statements(sql_blob):
        cur.execute(stmt)


def apply_sqlite():
    if sqlite3 is None:
        raise RuntimeError("sqlite3 module not available")

    db_path = config.require_sqlite_path()
    base_sql = load_sql("schema_base.sql")
    sqlite_sql = load_sql("schema_sqlite.sql")

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.executescript(base_sql)
        cursor.executescript(sqlite_sql)
        _ensure_sqlite_column(
            conn,
            table="access_reviews",
            column="ai_risk_summary",
            column_def="TEXT",
        )
        _ensure_sqlite_column(conn, "roles", "policy_document", "TEXT")
        _ensure_sqlite_column(conn, "roles", "observed_at", "TIMESTAMP")
        _ensure_sqlite_column(conn, "access_reviews", "reviewer_sub", "TEXT")
        _ensure_sqlite_column(conn, "remediation_approvals", "discovery_run_id", "TEXT")
        _ensure_sqlite_column(conn, "remediation_claims", "fencing_token", "INTEGER NOT NULL DEFAULT 0")
        cursor.execute(
            "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
            (config.SCHEMA_VERSION,),
        )
        conn.commit()
        logger.log(
            action="migrate",
            status="success",
            message=f"Applied schema version {config.SCHEMA_VERSION} to SQLite at {db_path}",
            details={"db_path": db_path},
        )
    finally:
        conn.close()


def apply_postgres():
    if psycopg2 is None:
        raise RuntimeError("psycopg2 is required for Postgres migrations")

    base_sql = load_sql("schema_base.sql")
    pg_sql = load_sql("schema_postgres.sql")

    conn = psycopg2.connect(
        config.get_db_url(),
        connect_timeout=10,  # Phase 1 default safety
    )
    try:
        with conn:
            with conn.cursor() as cur:
                _execute_statements(cur, base_sql)
                if pg_sql.strip():
                    _execute_statements(cur, pg_sql)
                cur.execute(
                    """
        INSERT INTO schema_version (version, applied_at)
                    VALUES (%s, NOW()) ON CONFLICT (version) DO NOTHING
                    """,
                    (config.SCHEMA_VERSION,),
                )
        logger.log(
            action="migrate",
            status="success",
            message=f"Applied schema version {config.SCHEMA_VERSION} to Postgres",
        )
    finally:
        conn.close()


def _ensure_sqlite_column(conn, table: str, column: str, column_def: str):
    """
    Add a column if it does not exist (SQLite has no IF NOT EXISTS for columns).
    Identifiers are allow-listed to prevent SQL injection.
    """
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table):
        raise ValueError(f"Invalid table name: {table!r}")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", column):
        raise ValueError(f"Invalid column name: {column!r}")
    if not re.fullmatch(r"[A-Za-z0-9_ ()]+", column_def):
        raise ValueError(f"Invalid column definition: {column_def!r}")
    cur = conn.cursor()
    cur.execute(f'PRAGMA table_info("{table}")')
    existing = {row[1] for row in cur.fetchall()}
    if column not in existing:
        cur.execute(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {column_def}')


def main():
    if config.db_is_sqlite():
        apply_sqlite()
    else:
        apply_postgres()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover
        logger.log("migrate", "error", f"Migration failed: {exc}", level="ERROR")
        sys.exit(1)

