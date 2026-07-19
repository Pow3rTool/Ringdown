"""ringdown.collector — the hot path: ingest -> store -> match -> dispatch.

One long-running process. Listens syslog (UDP+TCP), parses + template-mines +
batch-inserts to Postgres (ported from the Ringdown prototype), matches the in-memory L1
ruleset per line, and dispatches through the pluggable target coordinator. The
ruleset refreshes on Postgres ``rules_changed`` NOTIFY, never per-line.

  listeners -> asyncio.Queue -> batched flush -> Router.consider -> Coordinator

Talks to the control-plane (ringdown.mcp_server) ONLY through Postgres — no
direct IPC. Run:  python -m ringdown.collector
"""
from __future__ import annotations

import asyncio
import signal
import sys
from datetime import datetime, timedelta, timezone

import httpx
import psycopg
from psycopg.types.json import Jsonb

from . import config, db
from .dispatch import build_registry
from .incidents import Coordinator
from .obo import TurnstoneAdmin
from .router import Router
from .ruleset import Ruleset
from .syslog_parse import mine_template, parse_syslog


# --- DB writer — batched flush (ported from the Ringdown prototype) --------------------------
def _monday(dt: datetime):
    d = dt.astimezone(timezone.utc)
    return (d - timedelta(days=d.weekday())).date()


async def flush(conn, batch: list[dict]) -> None:
    if not batch:
        return
    weeks = {_monday(ev["ts"]) for ev in batch}
    async with conn.cursor() as cur:
        for ev in batch:
            ev["_fp"], ev["_tmpl"] = mine_template(ev["program"], ev["body"])
        for wk in weeks:
            await cur.execute("SELECT ringdown_ensure_week(%s)",
                              (datetime.combine(wk, datetime.min.time(), tzinfo=timezone.utc),))
        counts, tmpl = {}, {}
        for ev in batch:
            counts[ev["_fp"]] = counts.get(ev["_fp"], 0) + 1
            tmpl.setdefault(ev["_fp"], ev["_tmpl"])
        fp_id = {}
        for fp, tpl in tmpl.items():
            await cur.execute(
                "INSERT INTO log_templates (fingerprint, template, hits) VALUES (%s,%s,%s) "
                "ON CONFLICT (fingerprint) DO UPDATE SET last_seen = now(), "
                "hits = log_templates.hits + EXCLUDED.hits RETURNING id", (fp, tpl, counts[fp]))
            fp_id[fp] = (await cur.fetchone())[0]
        rows = [(ev["ts"], ev["source"], ev["facility"], ev["severity"], ev["severity_text"],
                 ev["program"], ev["body"], Jsonb(ev["attributes"]), ev["raw"], fp_id[ev["_fp"]])
                for ev in batch]
        await cur.executemany(
            "INSERT INTO events (ts, source, facility, severity, severity_text, program, body, "
            "attributes, raw, template_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", rows)
        seen = {}
        for ev in batch:
            seen[ev["source"]] = seen.get(ev["source"], 0) + 1
        for src, n in seen.items():
            await cur.execute(
                "INSERT INTO sources (source, events) VALUES (%s,%s) "
                "ON CONFLICT (source) DO UPDATE SET last_seen = now(), "
                "events = sources.events + EXCLUDED.events, active = true", (src, n))
    await conn.commit()


# --- listeners ---------------------------------------------------------------
class _UDP(asyncio.DatagramProtocol):
    def __init__(self, q):
        self.q = q

    def datagram_received(self, data, addr):
        try:
            self.q.put_nowait((data.decode("utf-8", "replace"), addr[0]))
        except asyncio.QueueFull:
            pass  # shed load rather than block the loop


async def _tcp_client(reader, writer, q):
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else None
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            s = line.decode("utf-8", "replace").rstrip("\r\n")
            if s:
                await q.put((s, peer_ip))
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        writer.close()


async def flusher(q, stop, router: Router):
    async with await psycopg.AsyncConnection.connect(config.DB_DSN, autocommit=False) as conn:
        print(f"[flusher] connected; batch<= {config.BATCH_MAX} / {config.BATCH_MS}ms", flush=True)
        loop = asyncio.get_event_loop()
        while not (stop.is_set() and q.empty()):
            batch = []
            try:
                first = await asyncio.wait_for(q.get(), timeout=0.5)
                batch.append(parse_syslog(*first))
            except asyncio.TimeoutError:
                continue
            deadline = loop.time() + config.BATCH_MS / 1000
            while len(batch) < config.BATCH_MAX:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    item = await asyncio.wait_for(q.get(), timeout=remaining)
                    batch.append(parse_syslog(*item))
                except asyncio.TimeoutError:
                    break
            try:
                await flush(conn, batch)
                router.consider(batch)  # L1 match + dispatch, off the commit path
            except Exception as e:
                print(f"[flusher] FLUSH FAILED ({type(e).__name__}: {e}); dropping {len(batch)}",
                      file=sys.stderr, flush=True)
                await conn.rollback()


async def maintenance(pool, stop) -> None:
    """Daily retention tick: drop expired event partitions + hide stale sources.
    Runs once shortly after start, then every RETENTION_INTERVAL. Disabled when
    RETENTION_DAYS <= 0. Retention is idempotent, so a missed tick self-heals."""
    if config.RETENTION_DAYS <= 0:
        print("[retention] disabled (RINGDOWN_RETENTION_DAYS=0)", flush=True)
        return
    print(f"[retention] on: keep {config.RETENTION_DAYS}d, tick "
          f"{config.RETENTION_INTERVAL:.0f}s", flush=True)
    while not stop.is_set():
        try:
            rows = await db.fetch(pool, "SELECT dropped_partition FROM ringdown_retention(%s)",
                                  (config.RETENTION_DAYS,))
            if rows:
                dropped = [r["dropped_partition"] for r in rows]
                print(f"[retention] dropped {len(dropped)} expired partition(s): {dropped}",
                      flush=True)
        except Exception as e:
            print(f"[retention] failed: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        try:
            await asyncio.wait_for(stop.wait(), timeout=config.RETENTION_INTERVAL)
        except asyncio.TimeoutError:
            pass


def _hostport(s: str):
    host, _, port = s.rpartition(":")
    return host or "0.0.0.0", int(port)


async def main() -> None:
    config.validate_collector()
    q = asyncio.Queue(maxsize=config.QUEUE_MAX)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    # dispatch stack
    http = httpx.AsyncClient(timeout=httpx.Timeout(15.0, read=90.0))
    admin = TurnstoneAdmin(config.TURNSTONE_URL, config.TURNSTONE_ADMIN_TOKEN,
                           token_ttl_hours=config.TOKEN_TTL_HOURS,
                           token_scopes=config.OBO_SCOPES, http=http)
    registry = build_registry(
        http, admin=admin, turnstone_url=config.TURNSTONE_URL,
        default_owner=config.TURNSTONE_DEFAULT_OWNER,
        default_project=config.TURNSTONE_DEFAULT_PROJECT, ntfy_url=config.NTFY_URL,
        ntfy_token=config.NTFY_TOKEN, ntfy_topic=config.NTFY_TOPIC,
        ntfy_allowed_hosts=config.NTFY_ALLOWED_HOSTS)

    pool = db.make_pool(config.DB_DSN)
    await pool.open()
    coordinator = Coordinator(pool, registry, reuse_ttl=config.INCIDENT_REUSE_TTL,
                              feed_interval=config.FEED_INTERVAL,
                              rate_ceiling=config.GLOBAL_RATE_CEILING,
                              fallback_ntfy_topic=config.FALLBACK_NTFY_TOPIC)
    ruleset = Ruleset(pool)
    await ruleset.reload()
    router = Router(ruleset, coordinator)
    print(f"[ringdown] live: {len(ruleset)} L1 rule(s) | dispatchers={sorted(registry)}", flush=True)

    # listeners
    transports, servers = [], []
    if config.SYSLOG_UDP:
        host, port = _hostport(config.SYSLOG_UDP)
        tr, _ = await loop.create_datagram_endpoint(lambda: _UDP(q), local_addr=(host, port))
        transports.append(tr)
        print(f"[udp] listening on {host}:{port}", flush=True)
    if config.SYSLOG_TCP:
        host, port = _hostport(config.SYSLOG_TCP)
        srv = await asyncio.start_server(lambda r, w: _tcp_client(r, w, q), host, port)
        servers.append(srv)
        print(f"[tcp] listening on {host}:{port}", flush=True)

    # live rule propagation: refresh the ruleset on Postgres NOTIFY (debounced)
    async def _on_notify(_payload: str):
        try:
            await ruleset.reload()
        except Exception as e:
            print(f"[ruleset] reload failed: {type(e).__name__}: {e}", file=sys.stderr, flush=True)

    fl = asyncio.create_task(flusher(q, stop, router))
    ls = asyncio.create_task(db.listen(config.DB_DSN, "rules_changed", _on_notify, stop))
    mt = asyncio.create_task(maintenance(pool, stop))

    # optional L2 semantic judge loop
    sem = None
    if config.LLM_URL:
        from .judge import SemanticJudge
        judge = SemanticJudge(pool, coordinator, router, http)
        sem = asyncio.create_task(judge.loop(stop))
        # Egress notice (sec review M5): windowed log content (which may carry IPs,
        # usernames, tokens-in-logs) is POSTed to this URL. Log it loudly so a
        # misconfigured/external endpoint is obvious in the journal.
        from urllib.parse import urlparse as _up
        print(f"[ringdown] L2 judge ON — model={config.LLM_MODEL} — SENDING WINDOWED LOG "
              f"CONTENT to {_up(config.LLM_URL).scheme}://{_up(config.LLM_URL).hostname} "
              f"(ensure this is your intended, trusted inference endpoint)", flush=True)

    await stop.wait()
    print("[main] draining…", flush=True)
    for tr in transports:
        tr.close()
    for srv in servers:
        srv.close()
    await fl
    await mt
    if sem:
        await sem
    await router.drain()
    await http.aclose()
    await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
