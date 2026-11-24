"""Create one fresh, named database on a dedicated local benchmark Postgres."""

import argparse
import re

import psycopg2
from psycopg2 import sql


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"iam_bench_[a-z0-9_]+", args.name):
        raise ValueError("Database name must start with iam_bench_ and use lowercase ASCII")
    conn = psycopg2.connect(args.admin_url, connect_timeout=10)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (args.name,))
            if cur.fetchone():
                raise RuntimeError(f"Database already exists: {args.name}")
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(args.name)))
    finally:
        conn.close()
    print(args.name)


if __name__ == "__main__":
    main()
