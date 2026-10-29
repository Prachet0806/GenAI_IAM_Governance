# scripts/migrate.py
import sys
import hashlib
import re
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


MIGRATIONS_DIR = ROOT / "sql" / "migrations"

# Additions for databases created before these baseline columns existed.
# This list is included in migration 0001's checksum and must remain stable.
SQLITE_BASELINE_COLUMNS = (
    ("access_reviews", "ai_risk_summary", "TEXT"),
    ("roles", "policy_document", "TEXT"),
    ("roles", "observed_at", "TIMESTAMP"),
    ("access_reviews", "reviewer_sub", "TEXT"),
    ("remediation_approvals", "discovery_run_id", "TEXT"),
    ("remediation_claims", "fencing_token", "INTEGER NOT NULL DEFAULT 0"),
)


def load_sql(name: str) -> str:
    path = MIGRATIONS_DIR / name
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    # Tolerate stray '#' header lines (not valid SQL); treat as comments.
    cleaned = "\n".join(
        line if not line.lstrip().startswith("#") else "-- " + line.lstrip()[1:]
        for line in content.splitlines()
    )
    return cleaned


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
        if (
            not in_single
            and not in_double
            and not in_line_comment
            and sql_blob.startswith("$$", i)
        ):
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


def _migration_plan(dialect: str):
    """Return ordered migration SQL and stable checksums for one backend."""
    if dialect not in ("sqlite", "postgres"):
        raise ValueError(f"Unsupported dialect: {dialect}")
    plan = []
    for path in sorted(MIGRATIONS_DIR.iterdir()):
        if not re.fullmatch(r"\d{4}_[a-z0-9_]+\.sql", path.name):
            continue
        version = path.stem
        engine_path = path.with_name(f"{version}.{dialect}.sql")
        common = load_sql(path.name)
        engine = load_sql(engine_path.name) if engine_path.exists() else ""
        compatibility = (
            repr(SQLITE_BASELINE_COLUMNS)
            if dialect == "sqlite" and version == "0001_baseline"
            else ""
        )
        digest = hashlib.sha256(
            (version + "\0" + common + "\0" + engine + "\0" + compatibility).encode(
                "utf-8"
            )
        ).hexdigest()
        plan.append((version, common, engine, digest))
    numbers = [int(version[:4]) for version, _, _, _ in plan]
    if not plan or numbers != list(range(1, len(plan) + 1)):
        raise RuntimeError("Migration files must start at 0001 and be consecutive")
    return plan


def _pending_migrations(cur, dialect: str):
    plan = _migration_plan(dialect)
    cur.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version TEXT PRIMARY KEY, checksum TEXT NOT NULL, "
        "applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    cur.execute("SELECT version, checksum FROM schema_migrations ORDER BY version")
    applied = cur.fetchall()
    expected = [(version, digest) for version, _, _, digest in plan]
    if applied != expected[: len(applied)]:
        raise RuntimeError("Applied migration history differs from migration files")
    return plan[len(applied) :]


def apply_sqlite():
    if sqlite3 is None:
        raise RuntimeError("sqlite3 module not available")
    db_path = config.require_sqlite_path()
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.cursor()
            for version, common, engine, digest in _pending_migrations(cur, "sqlite"):
                _execute_statements(cur, common)
                if version == "0001_baseline":
                    for table, column, definition in SQLITE_BASELINE_COLUMNS:
                        _ensure_sqlite_column(conn, table, column, definition)
                _execute_statements(cur, engine)
                cur.execute(
                    "INSERT INTO schema_migrations (version, checksum) VALUES (?, ?)",
                    (version, digest),
                )
                cur.execute(
                    "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
                    (config.SCHEMA_VERSION,),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        logger.log(
            "migrate",
            "success",
            f"Applied SQLite migrations at {db_path}",
            details={"db_path": db_path},
        )
    finally:
        conn.close()


def apply_postgres():
    if psycopg2 is None:
        raise RuntimeError("psycopg2 is required for Postgres migrations")
    conn = psycopg2.connect(config.get_db_url(), connect_timeout=10)
    try:
        with conn, conn.cursor() as cur:
            # Serialize concurrent installs, including before the ledger exists.
            cur.execute("SELECT pg_advisory_xact_lock(481701, 1)")
            for version, common, engine, digest in _pending_migrations(cur, "postgres"):
                _execute_statements(cur, common)
                _execute_statements(cur, engine)
                cur.execute(
                    "INSERT INTO schema_migrations (version, checksum) VALUES (%s, %s)",
                    (version, digest),
                )
                cur.execute(
                    "INSERT INTO schema_version (version) VALUES (%s) ON CONFLICT (version) DO NOTHING",
                    (config.SCHEMA_VERSION,),
                )
        logger.log("migrate", "success", "Applied Postgres migrations")
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
