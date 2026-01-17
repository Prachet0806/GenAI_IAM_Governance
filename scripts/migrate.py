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
        return f.read()


def _execute_statements(cur, sql_blob: str):
    """
    Execute multiple statements separated by semicolons (simple splitter).
    """
    for statement in sql_blob.split(";"):
        stmt = statement.strip()
        if not stmt:
            continue
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
        config.DB_URL,
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
                    VALUES (%s, NOW())
                    ON CONFLICT (version) DO UPDATE SET applied_at = EXCLUDED.applied_at
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
    """
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cur.fetchall()}
    if column not in existing:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_def}")


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

