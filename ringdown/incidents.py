"""ringdown.incidents — the dispatch coordinator (state, dedup, fallback).

This owns everything a Dispatcher deliberately does NOT:

  * incident dedup — one open handle per (rule, target, source); repeat matches
    FEED it (reuse-TTL gated) instead of opening new ones, so a flapping link is
    one incident, not 500.
  * feed throttle — at most one feed per handle per ``feed_interval``.
  * fallback-to-ntfy — if a stateful dispatch throws OR its type is unavailable,
    degrade to a direct ntfy push so a human is never blind.
  * global rate ceiling — a loop-guard: cap agent-summoning opens/minute across
    ALL rules so a storm (or an agent's own remediation logging back in) can't
    fan out unbounded.
  * audit + firing history for every disposition.

The Dispatcher plugins stay pure "how to reach"; all of the above lives here.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import deque

from psycopg.types.json import Jsonb

from . import db
from .dispatch import DispatchResult, FireContext, Registry


class Coordinator:
    def __init__(self, pool, registry: Registry, *, reuse_ttl: float = 7200,
                 feed_interval: float = 60, rate_ceiling: int = 120,
                 fallback_ntfy_topic: str = ""):
        self._pool = pool
        self._reg = registry
        self._reuse_ttl = reuse_ttl
        self._feed_every = feed_interval
        self._rate_ceiling = rate_ceiling
        self._fallback_topic = fallback_ntfy_topic
        self._locks: dict[str, asyncio.Lock] = {}
        self._opens = deque()   # monotonic timestamps of recent opens (rate ceiling window)

    # -- rate ceiling (loop-guard) ---------------------------------------------
    def _rate_ok_for_open(self) -> bool:
        now = time.monotonic()
        while self._opens and now - self._opens[0] > 60.0:
            self._opens.popleft()
        return len(self._opens) < self._rate_ceiling

    def _note_open(self) -> None:
        self._opens.append(time.monotonic())

    # -- the per-(rule,target,source) dispatch decision ------------------------
    async def handle(self, ctx: FireContext, target: dict, *, dedup_source: str | None = None) -> str:
        """Dispatch one firing to one target. Returns the disposition string."""
        rule_id = ctx.rule["id"]
        tid = target["id"]
        src = dedup_source or ctx.event.get("source")
        key = f"{rule_id}:{tid}:{src}"
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            try:
                return await self._dispatch_locked(ctx, target, key)
            except Exception as e:
                # Any unexpected error -> fallback push, never a silent drop.
                detail = f"{type(e).__name__}: {str(e)[:160]}"
                await self._fallback(ctx, f"coordinator error: {detail}")
                await self._record(ctx, tid, key, "", "error", detail)
                return "error"

    async def _dispatch_locked(self, ctx: FireContext, target: dict, key: str) -> str:
        disp = self._reg.get(target["type"])
        if disp is None:
            # Bound to a type we can't dispatch (e.g. turnstone admin token absent).
            await self._fallback(ctx, f"no dispatcher for target type {target['type']!r}")
            await self._record(ctx, target["id"], key, "", "fallback",
                               f"unavailable type {target['type']}")
            return "fallback"

        inc = await db.fetchone(self._pool, "SELECT * FROM alert_incidents WHERE dedup_key = %s", (key,))
        now = time.time()
        reuse = (inc and inc["status"] == "open"
                 and inc.get("handle") is not None
                 and (now - inc["last_event_at"].timestamp()) < self._reuse_ttl)

        if reuse and disp.stateful:
            return await self._feed(ctx, target, disp, inc, key)
        if reuse and not disp.stateful:
            # stateless (ntfy): throttle repeat pushes on the same incident
            return await self._feed_stateless(ctx, target, disp, inc, key)
        return await self._open(ctx, target, disp, key)

    async def _open(self, ctx: FireContext, target: dict, disp, key: str) -> str:
        if disp.stateful and not self._rate_ok_for_open():
            # loop-guard: too many agent summons this minute — hold off, push instead.
            await self._fallback(ctx, "global rate ceiling hit — agent summon suppressed")
            await self._record(ctx, target["id"], key, "", "rate_limited", "rate ceiling")
            return "rate_limited"
        res: DispatchResult = await disp.open(ctx, target)
        if not res.ok:
            await self._fallback(ctx, res.detail)
            await self._record(ctx, target["id"], key, "", "fallback", res.detail)
            return "fallback"
        if disp.stateful:
            self._note_open()
        await self._upsert_incident(key, ctx, target["id"], res.handle)
        await self._record(ctx, target["id"], key, res.handle, "opened", res.detail)
        await self._mark_fired(ctx.rule["id"])
        return "opened"

    async def _feed(self, ctx: FireContext, target: dict, disp, inc, key: str) -> str:
        now = time.time()
        last_fed = inc["last_fed_at"].timestamp() if inc["last_fed_at"] else 0
        throttled = (now - last_fed) < self._feed_every
        if not throttled:
            res: DispatchResult = await disp.feed(ctx, target, inc["handle"])
            if res.gone:
                return await self._open(ctx, target, disp, key)
            if not res.ok:
                await self._fallback(ctx, res.detail)
                await self._record(ctx, target["id"], key, inc["handle"], "fallback", res.detail)
                # still bump the incident so we don't hammer
                await self._bump_incident(key, fed=False)
                return "fallback"
        await self._bump_incident(key, fed=not throttled)
        await self._record(ctx, target["id"], key, inc["handle"],
                          "throttled" if throttled else "fed", "")
        return "throttled" if throttled else "fed"

    async def _feed_stateless(self, ctx: FireContext, target: dict, disp, inc, key: str) -> str:
        now = time.time()
        last_fed = inc["last_fed_at"].timestamp() if inc["last_fed_at"] else 0
        if (now - last_fed) < self._feed_every:
            await self._bump_incident(key, fed=False)
            await self._record(ctx, target["id"], key, "", "throttled", "")
            return "throttled"
        res = await disp.feed(ctx, target, "")
        await self._bump_incident(key, fed=True)
        await self._record(ctx, target["id"], key, "", "fed" if res.ok else "fallback", res.detail)
        return "fed" if res.ok else "fallback"

    # -- fallback ntfy push (never blind) --------------------------------------
    async def _fallback(self, ctx: FireContext, reason: str) -> None:
        disp = self._reg.get("ntfy")
        if disp is None or not self._fallback_topic:
            return
        fake_target = {"id": None, "type": "ntfy",
                       "config": {"topic": self._fallback_topic}}
        title = f"Ringdown (no agent): {ctx.rule.get('name')} on {ctx.event.get('source')}"
        # public-safe: reason is our own text, summary is LLM-sanitized — never raw logs
        body = (f"[{ctx.event.get('severity_text') or '?'}] dispatch degraded: {reason[:120]}. "
                f"Investigate in Ringdown (source {ctx.event.get('source')}).")
        # push via a minimal ctx clone carrying a safe summary
        push_ctx = FireContext(rule=ctx.rule, event=ctx.event, safe_summary=body)
        try:
            await disp.open(push_ctx, fake_target)
        except Exception:
            pass  # best-effort; the audit row below is the durable record

    # -- persistence -----------------------------------------------------------
    async def _upsert_incident(self, key: str, ctx: FireContext, target_id, handle: str) -> None:
        await db.execute(self._pool,
            "INSERT INTO alert_incidents (dedup_key, rule_id, target_id, source, handle, owner_user, "
            "last_fed_at, event_count, status) VALUES (%s,%s,%s,%s,%s,%s, now(), 1, 'open') "
            "ON CONFLICT (dedup_key) DO UPDATE SET handle = EXCLUDED.handle, "
            "owner_user = EXCLUDED.owner_user, opened_at = now(), last_event_at = now(), "
            "last_fed_at = now(), event_count = 1, status = 'open'",
            (key, ctx.rule["id"], target_id, ctx.event.get("source"), handle,
             ctx.owner_user or None))

    async def _bump_incident(self, key: str, *, fed: bool) -> None:
        await db.execute(self._pool,
            "UPDATE alert_incidents SET last_event_at = now(), event_count = event_count + 1"
            + (", last_fed_at = now()" if fed else "") + " WHERE dedup_key = %s", (key,))

    async def _record(self, ctx: FireContext, target_id, key: str, handle: str,
                       disposition: str, detail: str) -> None:
        await db.execute(self._pool,
            "INSERT INTO alert_events (rule_id, target_id, source, summary, sample, dedup_key, "
            "notified, disposition) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (ctx.rule["id"], target_id, ctx.event.get("source"),
             f"{ctx.rule.get('name')}: {ctx.event.get('body')}"[:500],
             Jsonb({"handle": handle, "disposition": disposition, "detail": detail,
                    "line": (ctx.event.get("raw") or "")[:500]}),
             key, disposition in ("opened", "fed", "ntfy"), disposition))
        await db.execute(self._pool,
            "INSERT INTO audit (actor_oid, action, detail, ok) VALUES ('collector', 'dispatch', %s, %s)",
            (Jsonb({"rule_id": ctx.rule["id"], "target_id": target_id, "disposition": disposition,
                    "source": ctx.event.get("source"), "handle": handle, "detail": detail[:200]}),
             disposition in ("opened", "fed", "throttled")))

    async def _mark_fired(self, rule_id) -> None:
        await db.execute(self._pool, "UPDATE alert_rules SET last_fired = now() WHERE id = %s", (rule_id,))

    # -- operational notice (not a rule firing) --------------------------------
    async def notify_ops(self, title: str, body: str, *, tags=None) -> bool:
        """Best-effort operational push to the fallback ntfy topic — for system
        signals like 'the semantic judge is blind'. Public-safe: pass no sensitive
        detail. Returns True if it went out; never raises."""
        disp = self._reg.get("ntfy")
        if disp is None or not self._fallback_topic or not hasattr(disp, "push_system"):
            return False
        target = {"id": None, "type": "ntfy", "config": {"topic": self._fallback_topic}}
        try:
            res = await disp.push_system(target, title, body, priority="high", tags=tags)
            return bool(getattr(res, "ok", False))
        except Exception:
            return False
