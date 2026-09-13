"""Queue integration tests use an isolated PostgreSQL schema, never deployment data.

Set RINGDOWN_TEST_DSN to a disposable PostgreSQL instance to run them.
"""
import asyncio
import os
import secrets
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest

from ringdown import db
from ringdown.agent_queue import AgentQueue, group_key, queue_status
from ringdown.dispatch.base import Dispatcher, DispatchResult, FireContext
from ringdown.dispatch.turnstone import TurnstoneDispatcher
from test_dispatch import FakeAdmin, FakeHTTP, FakeResp, _ctx


def test_grouping_defaults_and_identity_boundaries():
    a = _ctx(owner="alice")
    b = replace(a, event={**a.event, "source": "host-b"})
    target = {"id": 2}
    assert group_key(a, target) != group_key(b, target)
    a = replace(a, rule={**a.rule, "group_by": "rule"})
    b = replace(b, rule=a.rule)
    assert group_key(a, target) == group_key(b, target)
    assert group_key(a, target) != group_key(replace(a, owner_user="bob"), target)
    assert group_key(a, target) != group_key(replace(a, rule={**a.rule, "project_id": "other"}), target)
    with pytest.raises(ValueError):
        group_key(replace(a, rule={**a.rule, "group_by": "typo"}), target)


@pytest.mark.parametrize("status,accepted", [("ok", True), ("queued", True), ("queue_full", False),
                                           ("attachments_busy", False), (None, False)])
async def test_send_requires_application_ack(status, accepted):
    http = FakeHTTP(FakeResp(200, {"status": status}))
    disp = TurnstoneDispatcher(http, FakeAdmin(), base_url="http://ts")
    result = await disp.feed(_ctx(owner="alice"), {}, "ws")
    assert result.ok == accepted


@pytest.mark.parametrize("state,live,gone", [("closed", None, True), ("deleted", None, True),
                                           ("closed", {"state": "thinking"}, False),
                                           ("idle", {"state": "idle"}, False), ("idle", None, False)])
async def test_lifecycle_reads_do_not_rehydrate(state, live, gone):
    http = FakeHTTP(FakeResp(200, {"persisted": {"ws_id": "ws", "user_id": "alice", "state": state},
                                    "live": live}))
    disp = TurnstoneDispatcher(http, FakeAdmin(), base_url="http://ts")
    result = await disp.inspect(_ctx(owner="alice"), {}, "ws")
    assert result.ok and result.gone == gone
    assert http.calls[0]["url"] == "http://ts/v1/api/cluster/ws/ws/detail?limit=0"


@pytest.mark.parametrize("http_status", [401, 403, 404, 500])
async def test_lifecycle_errors_are_not_closure(http_status):
    disp = TurnstoneDispatcher(FakeHTTP(FakeResp(http_status)), FakeAdmin(), base_url="http://ts")
    result = await disp.inspect(_ctx(owner="alice"), {}, "ws")
    assert not result.ok and not result.gone


async def test_lifecycle_owner_mismatch_is_unknown():
    disp = TurnstoneDispatcher(FakeHTTP(FakeResp(200, {"persisted": {
        "ws_id": "ws", "user_id": "bob", "state": "closed"}})), FakeAdmin(), base_url="http://ts")
    result = await disp.inspect(_ctx(owner="alice"), {}, "ws")
    assert not result.ok and not result.gone


async def test_create_reserves_id_without_triggering_initial_message():
    http = FakeHTTP(FakeResp(200, {"ws_id": "reserved"}))
    disp = TurnstoneDispatcher(http, FakeAdmin(), base_url="http://ts")
    result = await disp.open(replace(_ctx(owner="alice"), request_id="reserved"), {})
    assert result.ok
    assert http.calls[0]["url"].endswith("?ws_id=reserved")
    assert "initial_message" not in http.calls[0]["json"]


class FakeAgent(Dispatcher):
    type, stateful = "turnstone", True

    def __init__(self):
        self.created, self.sends, self.states = [], [], {}
        self.queue_full = False
        self.ambiguous = False
        self.refuse = False
        self.unknown = set()
        self.closed_at = None

    async def prepare(self, ctx, target):
        return replace(ctx, owner_user=ctx.owner_user or "alice",
                       rule={**ctx.rule, "project_id": ctx.rule.get("project_id") or "proj"})

    async def open(self, ctx, target):
        self.created.append(ctx.request_id)
        if self.refuse:
            return DispatchResult(ok=False, detail="429", meta={"retry_create": True})
        self.states[ctx.request_id] = "idle"
        if self.ambiguous:
            self.unknown.add(ctx.request_id)
            return DispatchResult(ok=False, detail="timeout", meta={"ambiguous": True})
        return DispatchResult(ok=True, handle=ctx.request_id)

    async def inspect(self, ctx, target, handle):
        if handle in self.unknown:
            return DispatchResult(ok=False, detail="unreachable")
        state = self.states.get(handle, "closed")
        return DispatchResult(ok=True, handle=handle, gone=state == "closed",
                              meta={"state": state, "live": state != "closed", "project_id": "proj",
                                    "closed_at": self.closed_at})

    async def feed(self, ctx, target, handle):
        if self.queue_full:
            return DispatchResult(ok=False, detail="queue_full", meta={"send_status": "queue_full"})
        self.sends.append((handle, ctx.follow_up, ctx.delivery_id))
        return DispatchResult(ok=True, handle=handle, meta={"send_status": "queued"})


@pytest.fixture
async def queue_db():
    dsn = os.environ.get("RINGDOWN_TEST_DSN")
    if not dsn:
        pytest.skip("RINGDOWN_TEST_DSN not set (disposable PostgreSQL required)")
    schema = "ringdown_test_" + secrets.token_hex(8)
    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
        await conn.execute(f'CREATE SCHEMA "{schema}"')
    test_dsn = psycopg.conninfo.make_conninfo(dsn, options=f"-c search_path={schema},public")
    pool = db.make_pool(test_dsn, max_size=6)
    await pool.open()
    try:
        async with pool.connection() as conn:
            # Minimal dependencies: the release migration is exercised verbatim.
            await conn.execute("""
                CREATE TABLE alert_rules(id bigint PRIMARY KEY, name text, owner_user text DEFAULT 'alice',
                  project_id text DEFAULT 'proj', created_by_upn text, enabled boolean DEFAULT true, last_fired timestamptz);
                CREATE TABLE targets(id bigint PRIMARY KEY, type text DEFAULT 'turnstone', project_id text DEFAULT 'proj');
                CREATE TABLE rule_targets(rule_id bigint, target_id bigint);
                CREATE TABLE alert_events(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                  rule_id bigint REFERENCES alert_rules(id), target_id bigint REFERENCES targets(id), source text,
                  fired_at timestamptz DEFAULT now(), summary text, sample jsonb DEFAULT '{}', dedup_key text,
                  disposition text, notified boolean DEFAULT false);
                CREATE TABLE alert_incidents(handle text,rule_id bigint,target_id bigint,source text,dedup_key text,
                  owner_user text,opened_at timestamptz,last_fed_at timestamptz,status text);
                CREATE TABLE audit(actor_oid text,action text,detail jsonb);
                INSERT INTO alert_rules(id,name) VALUES (1,'ssh');
                INSERT INTO targets(id) VALUES (2);
                INSERT INTO rule_targets VALUES (1,2);
            """, prepare=False)
            migration = (Path(__file__).parents[1] / "ringdown/agent_schema.sql").read_text()
            await conn.execute(migration, prepare=False)
            await conn.execute(migration, prepare=False)  # idempotent
        yield pool
    finally:
        await pool.close()
        async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
            # Only this fixture's validated, randomly named isolated schema.
            await conn.execute(f'DROP SCHEMA "{schema}" CASCADE')


def event(host="host-a", grouping="host"):
    return FireContext(rule={"id": 1, "name": "ssh", "group_by": grouping, "project_id": "proj"},
                       event={"source": host, "body": "login", "severity_text": "info"},
                       owner_user="alice", seed="Investigate the SSH alert", follow_up=f"New login on {host}")


async def ready(pool):
    await db.execute(pool, "UPDATE agent_pending SET available_at=now()")
    await db.execute(pool, "UPDATE agent_workstreams SET checked_at=NULL")


async def test_host_default_and_global_cap_across_collectors(queue_db):
    agent = FakeAgent()
    q = AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0)
    await asyncio.gather(*(q.enqueue(event(f"host-{i}"), {"id": 2, "type": "turnstone"}) for i in range(8)))
    other = AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0)
    await asyncio.gather(q.tick(), other.tick())
    assert len(agent.created) == 4
    status = await queue_status(queue_db)
    assert status["active_workstreams"] == 4 and status["pending_events"] == 4
    agent.states[agent.created[0]] = "closed"
    await ready(queue_db)
    await other.tick()
    assert len(agent.created) == 5  # one slot released, one FIFO group admitted
    assert (await queue_status(queue_db))["active_workstreams"] == 4


async def test_rule_group_batches_hosts_and_survives_restart(queue_db):
    await db.execute(queue_db, "UPDATE alert_rules SET group_by='rule'")
    agent = FakeAgent()
    q = AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0)
    await asyncio.gather(*(q.enqueue(event(f"host-{i}", "rule"), {"id": 2, "type": "turnstone"}) for i in range(30)))
    await AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0).tick()
    assert len(agent.created) == len(agent.sends) == 1
    assert (await queue_status(queue_db))["pending_events"] == 10
    await q.tick()
    assert len(agent.created) == 1 and len(agent.sends) == 2
    assert (await queue_status(queue_db))["pending_events"] == 0


async def test_queue_full_retries_same_chat_without_loss(queue_db):
    agent = FakeAgent()
    agent.queue_full = True
    q = AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0)
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await q.tick()
    assert len(agent.created) == 1 and not agent.sends
    assert (await queue_status(queue_db))["pending_events"] == 1
    agent.queue_full = False
    await ready(queue_db)
    await AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0).tick()
    assert len(agent.created) == len(agent.sends) == 1


async def test_unknown_create_does_not_retry_or_release_capacity(queue_db):
    agent = FakeAgent()
    agent.ambiguous = True
    q = AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0, max_active=1)
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await q.tick()
    await ready(queue_db)
    await q.enqueue(event("host-b"), {"id": 2, "type": "turnstone"})
    await q.tick()
    assert len(agent.created) == 1
    assert (await queue_status(queue_db))["pending_events"] == 2
    agent.unknown.clear()
    await ready(queue_db)
    await q.tick()
    assert len(agent.created) == len(agent.sends) == 1


async def test_ttl_does_not_replace_idle_and_group_change_adopts(queue_db):
    agent = FakeAgent()
    q = AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0)
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await q.tick()
    await db.execute(queue_db, "UPDATE agent_workstreams SET opened_at=now()-interval '10 days'")
    await db.execute(queue_db, "UPDATE alert_rules SET group_by='rule'")
    await q.enqueue(event("host-b", "rule"), {"id": 2, "type": "turnstone"})
    await q.tick()
    assert len(agent.created) == 1 and len(agent.sends) == 2


async def test_disabled_rule_cancels_pending_without_freeing_live_slot(queue_db):
    agent = FakeAgent()
    agent.queue_full = True
    q = AgentQueue(queue_db, {"turnstone": agent})
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await q.tick()
    await db.execute(queue_db, "UPDATE alert_rules SET enabled=false")
    await q.tick()
    status = await queue_status(queue_db)
    assert status["pending_events"] == 0 and status["active_workstreams"] == 1
    row = await db.fetchone(queue_db, "SELECT disposition FROM alert_events")
    assert row["disposition"] == "cancelled"


async def test_closing_resolves_old_backlog_but_not_new_events(queue_db):
    agent = FakeAgent()
    q = AgentQueue(queue_db, {"turnstone": agent}, feed_interval=60)
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await q.tick()
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    agent.closed_at = datetime.now(timezone.utc).isoformat()
    agent.states[agent.created[0]] = "closed"
    await ready(queue_db)
    await q.tick()
    assert (await queue_status(queue_db))["pending_events"] == 0
    assert len(agent.created) == 1
    assert (await db.fetchone(queue_db, "SELECT count(*) AS n FROM alert_events WHERE disposition='resolved'"))["n"] == 1
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await q.tick()
    assert len(agent.created) == 2


async def test_post_close_arrival_before_poll_is_not_discarded(queue_db):
    agent = FakeAgent()
    q = AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0)
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await q.tick()
    agent.closed_at = datetime.now(timezone.utc).isoformat()
    agent.states[agent.created[0]] = "closed"
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await ready(queue_db)
    await q.tick()
    assert len(agent.created) == 2
    assert (await queue_status(queue_db))["pending_events"] == 0


async def test_semantic_default_keeps_existing_cross_source_group(queue_db):
    agent = FakeAgent()
    q = AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0)
    await q.enqueue(event("host-a"), {"id": 2, "type": "turnstone"}, dedup_source="semantic")
    await q.tick()
    await q.enqueue(event("host-b"), {"id": 2, "type": "turnstone"}, dedup_source="semantic")
    await q.tick()
    assert len(agent.created) == 1 and len(agent.sends) == 2


async def test_confirmed_create_refusal_retries_reserved_id(queue_db):
    agent = FakeAgent()
    agent.refuse = True
    q = AgentQueue(queue_db, {"turnstone": agent}, feed_interval=0)
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await q.tick()
    agent.refuse = False
    await ready(queue_db)
    await q.tick()
    assert len(agent.created) == 2 and len(set(agent.created)) == 1
    assert len(agent.sends) == 1


async def test_rate_ceiling_keeps_pending_not_dropped(queue_db):
    agent = FakeAgent()
    q = AgentQueue(queue_db, {"turnstone": agent}, rate_ceiling=0)
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await q.tick()
    assert not agent.created
    assert (await queue_status(queue_db))["pending_events"] == 1


async def test_owner_change_never_borrows_old_owner_credentials(queue_db):
    agent = FakeAgent()
    q = AgentQueue(queue_db, {"turnstone": agent})
    await q.enqueue(event(), {"id": 2, "type": "turnstone"})
    await db.execute(queue_db, "UPDATE alert_rules SET owner_user='bob'")
    await q.tick()
    assert not agent.created and not agent.sends
    status = await queue_status(queue_db)
    assert status["pending_events"] == 1
    assert "owner/project changed" in status["pending"][0]["waiting_reason"]


async def test_migration_imports_overwritten_handles_once(queue_db):
    await db.execute(queue_db,
        "INSERT INTO alert_events(rule_id,target_id,source,dedup_key,disposition,sample) VALUES "
        "(1,2,'host-a','1:2:host-a','opened','{\"handle\":\"old\"}'), "
        "(1,2,'host-a','1:2:host-a','opened','{\"handle\":\"new\"}')")
    migration = (Path(__file__).parents[1] / "ringdown/agent_schema.sql").read_text()
    async with queue_db.connection() as conn:
        await conn.execute(migration, prepare=False)
    await db.execute(queue_db, "UPDATE agent_workstreams SET status='closed' WHERE handle='old'")
    async with queue_db.connection() as conn:
        await conn.execute(migration, prepare=False)
    rows = await db.fetch(queue_db, "SELECT handle,status,group_source FROM agent_workstreams ORDER BY handle")
    assert rows == [{"handle": "new", "status": "open", "group_source": "host-a"},
                    {"handle": "old", "status": "closed", "group_source": "host-a"}]
