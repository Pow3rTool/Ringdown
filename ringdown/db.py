"""ringdown.db — pooled Postgres access + the LISTEN/NOTIFY listener.

Small helpers shared by the collector and the MCP. The `listen()` coroutine is
the collector half of the live-rule-propagation spine: it holds one
dedicated connection on the `rules_changed` channel and invokes a callback on
each NOTIFY so the in-memory ruleset refreshes on change, not on a timer.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import psycopg
from psycopg.rows import dict_row


def make_pool(dsn: str, *, min_size: int = 1, max_size: int = 4):
    """A dict-row async pool (opened by the caller via `await pool.open()`).

    ``psycopg_pool`` is imported lazily so modules that only ever receive a pool
    (tests, the dispatch layer) import without the pool dist installed."""
    from psycopg_pool import AsyncConnectionPool
    return AsyncConnectionPool(dsn, min_size=min_size, max_size=max_size, open=False,
                               kwargs={"row_factory": dict_row})


async def fetch(pool: AsyncConnectionPool, sql: str, params=()):
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(sql, params)
        return await cur.fetchall()


async def fetchone(pool: AsyncConnectionPool, sql: str, params=()):
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(sql, params)
        return await cur.fetchone()


async def execute(pool: AsyncConnectionPool, sql: str, params=()):
    """Run a write; return the RETURNING row if the statement produced one."""
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(sql, params)
        row = await cur.fetchone() if cur.description else None
    return row  # pool commits on clean block exit


async def listen(dsn: str, channel: str, on_notify: Callable[[str], Awaitable[None]],
                 stop: asyncio.Event) -> None:
    """Hold a dedicated autocommit connection LISTENing on `channel`; call
    `on_notify(payload)` per notification until `stop` is set. Reconnects with
    backoff if the connection drops — a lost listener must not silently freeze
    the ruleset (it would then run stale rules forever)."""
    backoff = 1.0
    while not stop.is_set():
        try:
            async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
                await conn.execute(f"LISTEN {channel}")
                backoff = 1.0
                # Prime once on (re)connect so a NOTIFY missed while disconnected
                # can't leave us stale.
                await on_notify("")
                # notifies(timeout=…) ends the generator after an idle interval so we
                # can re-check `stop` without cancelling a half-consumed __anext__.
                while not stop.is_set():
                    async for notify in conn.notifies(timeout=5.0):
                        await on_notify(notify.payload)
                        if stop.is_set():
                            break
        except Exception:
            if stop.is_set():
                break
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
