"""Durable agent delivery, lifecycle reconciliation and cluster-wide admission.

Only the scheduler calls stateful targets. A PostgreSQL session advisory lock
serializes schedulers, even across collector replicas. Each create reservation
is committed BEFORE the HTTP call and counts toward the active cap. Unknown
create outcomes are reconciled, never retried with a new workstream id.

Delivery is at-least-once within the SAME chat after an ambiguous send response;
Turnstone's client_send_id is correlation, not a durable idempotency contract.
"""
from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import replace
from datetime import datetime, timezone

from psycopg.types.json import Jsonb

from .dispatch import FireContext
from . import db

SCHEDULER_LOCK = 0x52494E47444F574E  # RINGDOWN; signed bigint, shared by all replicas


def group_key(ctx: FireContext, target: dict, source: str | None = None) -> str:
    grouping = ctx.rule.get("group_by", "host")
    if grouping not in ("host", "rule"):
        raise ValueError("group_by must be host or rule")
    return json.dumps([ctx.rule["id"], target["id"], grouping,
                       (source or ctx.event.get("source")) if grouping == "host" else None,
                       ctx.owner_user, ctx.rule.get("project_id") or ""], separators=(",", ":"))


def pack(ctx: FireContext) -> dict:
    # Do not serialize regex objects, target credentials, or entire rule lists.
    return {
        "rule": {k: ctx.rule.get(k) for k in
                 ("id", "name", "kind", "group_by", "project_id", "created_by_upn")},
        "event": {k: str(ctx.event.get(k) or "") for k in
                  ("source", "severity_text", "ts", "body", "raw")},
        "owner_user": ctx.owner_user, "seed": ctx.seed,
        "follow_up": ctx.follow_up, "safe_summary": ctx.safe_summary,
    }


async def queue_status(pool, max_active=4):
    """Body-free operational visibility; remote queue depth is deliberately null."""
    counts = await db.fetchone(pool,
        "SELECT (SELECT count(*) FROM agent_workstreams WHERE status<>'closed') AS active_workstreams, "
        "(SELECT count(*) FROM agent_pending) AS pending_events, "
        "(SELECT count(DISTINCT dedup_key) FROM agent_pending) AS pending_groups")
    workstreams = await db.fetch(pool,
        "SELECT handle,rule_id,target_id,source,status,opened_at,checked_at,last_state,last_detail,last_sent_at "
        "FROM agent_workstreams WHERE status<>'closed' ORDER BY opened_at LIMIT 100")
    groups = await db.fetch(pool,
        "SELECT dedup_key,rule_id,target_id,count(*) AS pending_events,min(created_at) AS oldest_event_at, "
        "min(available_at) AS retry_at,(SELECT p2.last_detail FROM agent_pending p2 "
        "WHERE p2.dedup_key=p.dedup_key ORDER BY p2.id LIMIT 1) AS waiting_reason "
        "FROM agent_pending p GROUP BY dedup_key,rule_id,target_id ORDER BY min(id) LIMIT 100")
    return {**counts, "max_active_workstreams": max_active, "workstreams": workstreams,
            "pending": groups, "turnstone_queued_messages": None,
            "queue_depth_note": "Turnstone exposes acceptance/queue_full, not a supported exact queue-depth API. "
                                "pending_events counts durable events waiting in Ringdown, not messages in Turnstone."}


async def one(conn, sql, params=()):
    return await (await conn.execute(sql, params)).fetchone()


async def all_rows(conn, sql, params=()):
    return await (await conn.execute(sql, params)).fetchall()


class AgentQueue:
    def __init__(self, pool, registry, *, max_active=4, feed_interval=60,
                 poll_interval=10, rate_ceiling=120, batch_size=20):
        if not 1 <= max_active <= 4:
            raise ValueError("max_active must be between 1 and 4")
        self.pool, self.registry = pool, registry
        self.max_active, self.feed_interval = max_active, max(0, feed_interval)
        self.poll_interval = max(1, poll_interval)
        self.rate_ceiling, self.batch_size = rate_ceiling, max(1, min(batch_size, 100))

    async def enqueue(self, ctx, target, *, dedup_source=None):
        ctx = await self.registry[target["type"]].prepare(ctx, target)
        key = group_key(ctx, target, dedup_source)
        async with self.pool.connection() as conn:
            current = await self._find_workstream(conn, ctx, target, ctx.rule.get("group_by", "host"),
                                                  json.loads(key)[3], lock=True)
            ev = await one(conn,
                "INSERT INTO alert_events(rule_id,target_id,source,summary,sample,dedup_key,disposition) "
                "VALUES (%s,%s,%s,%s,%s,%s,'queued') RETURNING id",
                (ctx.rule["id"], target["id"], ctx.event.get("source"),
                 f"{ctx.rule.get('name')}: {ctx.event.get('body')}"[:500],
                 Jsonb({"disposition": "queued"}), key))
            await conn.execute(
                "INSERT INTO agent_pending(event_id,rule_id,target_id,dedup_key,payload,assigned_handle) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (ev["id"], ctx.rule["id"], target["id"], key, Jsonb(pack(ctx)),
                 current["handle"] if current else None))
        return "queued"

    async def run(self, stop):
        while not stop.is_set():
            try:
                await self.tick()
            except Exception as e:
                # No log bodies or credentials in scheduler diagnostics.
                print(f"[agent-queue] tick failed ({type(e).__name__}); pending events retained", flush=True)
            try:
                await asyncio.wait_for(stop.wait(), self.poll_interval)
            except asyncio.TimeoutError:
                pass

    async def tick(self):
        async with self.pool.connection() as conn:
            await conn.set_autocommit(True)
            locked = False
            try:
                locked = (await one(conn, "SELECT pg_try_advisory_lock(%s) AS locked",
                                    (SCHEDULER_LOCK,)))["locked"]
                if not locked:
                    return
                await self._tick_locked(conn)
            finally:
                if locked and not conn.closed:
                    await conn.execute("SELECT pg_advisory_unlock(%s)", (SCHEDULER_LOCK,))
                if not conn.closed:
                    await conn.set_autocommit(False)

    @staticmethod
    def _ws_context(ws):
        return FireContext(rule={"id": ws["rule_id"], "created_by_upn": ws["created_by_upn"],
                                 "project_id": ws["project_id"]}, event={}, owner_user=ws["owner_user"])

    async def _inspect(self, conn, ws):
        disp = self.registry.get(ws["target_type"])
        if disp is None:
            return None
        ctx = self._ws_context(ws)
        # Legacy rows may predate persisted owner resolution. Freeze it once.
        ctx = await disp.prepare(ctx, {"id": ws["target_id"]})
        res = await disp.inspect(ctx, {}, ws["handle"])
        state = res.meta.get("state") if res.ok else "unknown"
        status = "closed" if res.ok and res.gone else ws["status"]
        if res.ok and not res.gone and status in ("opening", "uncertain"):
            status = "open"
        async with conn.transaction():
            await conn.execute(
                "UPDATE agent_workstreams SET status=%s, checked_at=now(), last_state=%s, last_detail=%s, "
                "owner_user=%s, project_id=%s WHERE handle=%s",
                (status, state, res.detail[:300], ctx.owner_user,
                 res.meta.get("project_id", ws["project_id"]), ws["handle"]))
            if status == "closed":
                try:
                    closed_at = datetime.fromisoformat(str(res.meta.get("closed_at")))
                    if closed_at.tzinfo is None:
                        closed_at = closed_at.replace(tzinfo=timezone.utc)
                except (TypeError, ValueError):
                    closed_at = datetime.now(timezone.utc)
                await conn.execute("UPDATE alert_incidents SET status='closed' WHERE handle=%s", (ws["handle"],))
                await conn.execute("UPDATE agent_workstreams SET closed_at=%s WHERE handle=%s", (closed_at, ws["handle"]))
                resolved = await all_rows(conn,
                    "DELETE FROM agent_pending WHERE assigned_handle=%s AND created_at<=%s RETURNING event_id",
                    (ws["handle"], closed_at))
                if resolved:
                    await conn.execute("UPDATE alert_events SET disposition='resolved' WHERE id=ANY(%s)",
                                       ([r["event_id"] for r in resolved],))
        return res

    @staticmethod
    async def _find_workstream(conn, ctx, target, grouping, source, *, lock=False):
        return await one(conn,
            "SELECT * FROM agent_workstreams WHERE rule_id=%s AND target_id=%s AND status<>'closed' "
            "AND owner_user=%s AND project_id=%s AND (%s='rule' OR coalesce(group_source,source)=%s) "
            "ORDER BY opened_at DESC LIMIT 1" + (" FOR SHARE" if lock else ""),
            (ctx.rule["id"], target["id"], ctx.owner_user, ctx.rule.get("project_id") or "", grouping, source))

    async def _tick_locked(self, conn):
        # Poll even when no new events arrive, so closing a chat releases a slot.
        active = await all_rows(conn,
            "SELECT * FROM agent_workstreams WHERE status <> 'closed' AND "
            "(checked_at IS NULL OR checked_at < now()-interval '30 seconds') "
            "ORDER BY checked_at NULLS FIRST LIMIT 64")
        for ws in active:
            if ws["status"] != "opening" or ws["attempted"]:
                try:
                    await self._inspect(conn, ws)
                except Exception as e:
                    await conn.execute(
                        "UPDATE agent_workstreams SET checked_at=now(),last_state='unknown',last_detail=%s WHERE handle=%s",
                        (f"inspection failed ({type(e).__name__})", ws["handle"]))

        # Disabling/unbinding a rule is authoritative; don't deliver old work.
        async with conn.transaction():
            cancelled = await all_rows(conn,
                "DELETE FROM agent_pending p WHERE NOT EXISTS "
                "(SELECT 1 FROM alert_rules r JOIN rule_targets rt ON rt.rule_id=r.id "
                "WHERE r.id=p.rule_id AND rt.target_id=p.target_id AND r.enabled) RETURNING event_id")
            if cancelled:
                await conn.execute("UPDATE alert_events SET disposition='cancelled' WHERE id=ANY(%s)",
                                   ([r["event_id"] for r in cancelled],))

        groups = await all_rows(conn,
            "SELECT dedup_key, min(id) AS first_id FROM agent_pending "
            "GROUP BY dedup_key HAVING min(available_at)<=now() ORDER BY min(id) LIMIT 256")
        for group in groups:
            rows = await all_rows(conn, "SELECT * FROM agent_pending WHERE dedup_key=%s ORDER BY id LIMIT %s",
                                  (group["dedup_key"], self.batch_size))
            if not rows or rows[0]["available_at"] > datetime.now(timezone.utc):
                continue
            try:
                await self._deliver(conn, rows)
            except Exception as e:
                await self._defer(conn, rows, f"delivery failed ({type(e).__name__}); events retained")

    async def _defer(self, conn, rows, detail, seconds=30):
        await conn.execute(
            "UPDATE agent_pending SET available_at=now()+(%s * interval '1 second'), "
            "attempts=attempts+1,last_detail=%s WHERE id=ANY(%s)",
            (seconds, detail[:300], [r["id"] for r in rows]))

    async def _deliver(self, conn, rows):
        first = rows[0]
        ctx = FireContext(**first["payload"])
        target = await one(conn, "SELECT * FROM targets WHERE id=%s", (first["target_id"],))
        rule = await one(conn, "SELECT * FROM alert_rules WHERE id=%s", (first["rule_id"],))
        if not target or not rule:
            return
        disp = self.registry.get(target["type"])
        if not disp or not disp.stateful:
            await self._defer(conn, rows, "dispatcher unavailable")
            return
        current = await disp.prepare(replace(ctx, rule=rule, owner_user=rule.get("owner_user") or ""), target)
        if (current.owner_user != ctx.owner_user or
                current.rule.get("project_id") != ctx.rule.get("project_id")):
            await self._defer(conn, rows, "owner/project changed; operator reconciliation required", 300)
            return
        # A rule-wide group may adopt an existing host incident with the SAME
        # owner/project. Other existing chats are not closed and still count.
        logical_source = json.loads(first["dedup_key"])[3]
        ws = await self._find_workstream(conn, ctx, target, rule["group_by"], logical_source)
        if not ws:
            counts = await one(conn,
                "SELECT count(*) FILTER (WHERE status<>'closed') AS active, "
                "count(*) FILTER (WHERE opened_at>now()-interval '1 minute') AS recent FROM agent_workstreams")
            if counts["active"] >= self.max_active or counts["recent"] >= self.rate_ceiling:
                await self._defer(conn, rows, "waiting for active-workstream capacity", self.poll_interval)
                return
            handle = secrets.token_hex(16)
            ws = await one(conn,
                "INSERT INTO agent_workstreams(handle,rule_id,target_id,target_type,source,dedup_key,"
                "owner_user,project_id,created_by_upn,group_source,status) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'opening') RETURNING *",
                (handle, rule["id"], target["id"], target["type"], ctx.event.get("source"), first["dedup_key"],
                 ctx.owner_user, ctx.rule.get("project_id") or "", ctx.rule.get("created_by_upn") or "",
                 logical_source if logical_source is not None else ctx.event.get("source")))
        await conn.execute("UPDATE agent_pending SET assigned_handle=%s WHERE id=ANY(%s)",
                           (ws["handle"], [r["id"] for r in rows]))
        if ws["status"] == "opening" and not ws["attempted"]:
            # Commit reservation + attempted flag before creating. A crash or
            # timeout here cannot authorize a second fresh id on restart.
            await conn.execute("UPDATE agent_workstreams SET attempted=true,status='uncertain' WHERE handle=%s",
                               (ws["handle"],))
            res = await disp.open(replace(ctx, request_id=ws["handle"]), target)
            if not res.ok:
                if res.meta.get("retry_create"):
                    await conn.execute("UPDATE agent_workstreams SET attempted=false,status='opening' WHERE handle=%s",
                                       (ws["handle"],))
                await self._defer(conn, rows, res.detail)
                return
            if res.handle != ws["handle"]:
                await self._defer(conn, rows, "create returned unexpected handle; reconcile manually", 300)
                return
            await conn.execute("UPDATE agent_workstreams SET status='open' WHERE handle=%s", (ws["handle"],))
            ws["status"] = "open"
        res = await self._inspect(conn, ws)
        if not res or not res.ok or res.gone or not res.meta.get("live"):
            await self._defer(conn, rows, res.detail if res else "lifecycle unavailable")
            return
        if res.meta.get("project_id", "") != ctx.rule.get("project_id", ""):
            await self._defer(conn, rows, "workstream project mismatch; refusing delivery", 300)
            return
        if ws["last_sent_at"]:
            remaining = self.feed_interval - (datetime.now(timezone.utc) - ws["last_sent_at"]).total_seconds()
            if remaining > 0:
                await self._defer(conn, rows, "batching follow-up events", remaining)
                return
        # Bound follow-up size while preserving every event in the outbox.
        batch, parts, size = [], [], 0
        for row in rows:
            payload = row["payload"]
            text = payload["follow_up"] or payload["seed"]
            if batch and size + len(text) > 12000:
                break
            batch.append(row)
            parts.append(f"[Ringdown event {row['event_id']}]\n{text}")
            size += len(text)
        message = "\n\n".join(parts)
        if not ws["seeded"]:
            message = ctx.seed + "\n\n" + message
        delivery_id = f"ringdown_{batch[0]['event_id']}_{batch[-1]['event_id']}"
        res = await disp.feed(replace(ctx, follow_up=message, delivery_id=delivery_id), target, ws["handle"])
        if not res.ok:
            # A send 404 isn't proof of closure (may be ACL or unloaded node).
            await self._defer(conn, batch, res.detail)
            return
        disposition = "fed" if ws["seeded"] else "opened"
        async with conn.transaction():
            await conn.execute("UPDATE agent_workstreams SET seeded=true,last_sent_at=now(),last_detail=%s WHERE handle=%s",
                               (res.detail[:300], ws["handle"]))
            await conn.execute(
                "UPDATE alert_events SET notified=true,disposition=%s,sample=sample || %s WHERE id=ANY(%s)",
                (disposition, Jsonb({"handle": ws["handle"], "disposition": disposition,
                                    "send_status": res.meta.get("send_status"), "delivery_id": delivery_id}),
                 [r["event_id"] for r in batch]))
            await conn.execute("DELETE FROM agent_pending WHERE id=ANY(%s)", ([r["id"] for r in batch],))
            await conn.execute("UPDATE alert_rules SET last_fired=now() WHERE id=%s", (rule["id"],))
            await conn.execute(
                "INSERT INTO audit(actor_oid,action,detail) VALUES ('collector','agent_delivery',%s)",
                (Jsonb({"handle": ws["handle"], "rule_id": rule["id"], "target_id": target["id"],
                        "disposition": disposition, "event_count": len(batch), "delivery_id": delivery_id}),))
