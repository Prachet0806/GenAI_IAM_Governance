# common/db.py
import contextlib
import sqlite3
from typing import Any, Iterable, Tuple

from common import config

try:
    import psycopg2  # type: ignore
except ImportError:  # pragma: no cover
    psycopg2 = None  # type: ignore


class Database:
    """
    Lightweight DB helper that supports SQLite and Postgres based on DB_URL.
    - SQLite: enables foreign keys pragma.
    - Postgres: connect_timeout, autocommit off by default.
    """

    def __init__(self):
        # is_sqlite resolved per-connection (see get_connection) to avoid
        # import-time freezing; kept as snapshot for backwards compat.
        self.is_sqlite = config.db_is_sqlite()

    def _is_sqlite_now(self) -> bool:
        try:
            return config.db_is_sqlite()
        except Exception:
            return self.is_sqlite

    def _connect_sqlite(self, path: str | None = None):
        resolved = path or config.get_sqlite_path()
        if resolved == ":memory:":
            raise ValueError("sqlite :memory: is not supported for file-backed engine; set a file path.")
        conn = sqlite3.connect(resolved, timeout=15)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 15000;")
        return conn

    def _connect_postgres(self):
        if psycopg2 is None:
            raise RuntimeError("psycopg2 is required for Postgres connections")
        return psycopg2.connect(config.get_db_url(), connect_timeout=10)

    @contextlib.contextmanager
    def get_connection(self):
        is_sqlite = self._is_sqlite_now()
        conn = self._connect_sqlite() if is_sqlite else self._connect_postgres()
        try:
            yield conn
            # caller should commit; for safety commit on exit
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def prepare_sql(self, sql: str) -> str:
        """
        Convert SQLite-style ? placeholders to %s for Postgres.
        Skips ? inside quoted literals and Postgres JSON operators
        (? ?| ?& ??, and ? followed by a string literal like ? 'key').
        """
        if self._is_sqlite_now():
            return sql
        out = []
        in_single = False
        in_double = False
        i = 0
        n = len(sql)
        while i < n:
            ch = sql[i]
            if ch == "'" and not in_double:
                # handle '' escape
                if in_single and i + 1 < n and sql[i + 1] == "'":
                    out.append("''")
                    i += 2
                    continue
                in_single = not in_single
                out.append(ch)
            elif ch == '"' and not in_single:
                in_double = not in_double
                out.append(ch)
            elif ch == "?" and not in_single and not in_double:
                prev_c = sql[i - 1] if i > 0 else ""
                nxt = sql[i + 1] if i + 1 < n else ""
                # ??, ?|, ?& are operators, not placeholders
                if nxt in ("?", "|", "&"):
                    out.append("?")
                else:
                    # ? 'key' / ? "key" is the JSON existence operator
                    j = i + 1
                    while j < n and sql[j] in (" ", "\t", "\n", "\r"):
                        j += 1
                    if j < n and sql[j] in ("'", '"'):
                        out.append("?")
                    elif prev_c == "?":
                        out.append("?")
                    else:
                        out.append("%s")
            else:
                out.append(ch)
            i += 1
        return "".join(out)

    def execute(self, cursor, sql: str, params: Iterable[Any] = ()):
        prepared = self.prepare_sql(sql)
        # Avoid passing empty params to drivers that expect placeholders
        if params is None or (hasattr(params, "__len__") and len(params) == 0):
            cursor.execute(prepared)
        else:
            cursor.execute(prepared, params)

    def executemany(self, cursor, sql: str, seq_of_params: Iterable[Tuple[Any, ...]]):
        cursor.executemany(self.prepare_sql(sql), seq_of_params)


db = Database()

