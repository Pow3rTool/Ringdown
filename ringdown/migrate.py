"""Apply Ringdown's idempotent schema in one transaction.

Intended for a one-shot container using the same read-only ``/app/.env`` mount
as the services:

    python -m ringdown.migrate

Run this before restarting a release that requires new database objects.
"""
from __future__ import annotations

from pathlib import Path

import psycopg

from . import config


def main() -> None:
    if not config.DB_DSN:
        raise SystemExit("RINGDOWN_DB_DSN is required.")
    schema_path = Path(__file__).with_name("schema.sql")
    sql = schema_path.read_text(encoding="utf-8")
    with psycopg.connect(config.DB_DSN) as conn:
        # prepare=False selects libpq's simple-query protocol, which accepts the
        # schema's intentionally multi-statement SQL. The connection context
        # commits all DDL/data migrations together or rolls everything back.
        conn.execute(sql, prepare=False)
    print("[ringdown-migrate] schema applied successfully", flush=True)


if __name__ == "__main__":
    main()
