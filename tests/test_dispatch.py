"""Dispatcher + coordinator behaviour (fakes for HTTP + DB).

Covers the security-load-bearing bits: ntfy never leaks a raw log body onto a
public topic; the turnstone dispatcher fails CLOSED with no resolvable owner and
resolves the owner from the creator's UPN; the coordinator opens vs feeds vs
throttles, degrades to a fallback ntfy push when a dispatch fails, and suppresses
agent summons past the global rate ceiling (loop-guard).

Requires the runtime deps (httpx/psycopg/mcp) — run under the venv, not the jump box.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ringdown import incidents as inc_mod
from ringdown.dispatch import FireContext
from ringdown.dispatch.ntfy import NtfyDispatcher
from ringdown.dispatch.turnstone import TurnstoneDispatcher
from ringdown.incidents import Coordinator


# -- fakes --------------------------------------------------------------------
class FakeResp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHTTP:
    def __init__(self, resp=None):
        self.calls = []
        self._resp = resp or FakeResp(200, {"ws_id": "ws-real"})

    async def post(self, url, headers=None, json=None, content=None):
        self.calls.append({"url": url, "headers": headers, "json": json, "content": content})
        return self._resp

    async def get(self, url, headers=None):
        self.calls.append({"url": url, "headers": headers})
        return self._resp


class FakeAdmin:
    enabled = True

    def __init__(self, token="tok", resolved=""):
        self._token = token
        self._resolved = resolved

    async def token_for(self, user_id):
        return self._token

    async def resolve_owner(self, upn):
        return self._resolved


def _ctx(owner="", upn="", body="secret password hunter2 at 10.0.0.9"):
    rule = {"id": 1, "name": "bgp-flap", "created_by_upn": upn, "project_id": "proj-x"}
    event = {"source": "rtr-1", "severity": 17, "severity_text": "err",
             "program": "%BGP-3", "body": body, "raw": body, "ts": datetime(2026, 6, 30, tzinfo=timezone.utc)}
    return FireContext(rule=rule, event=event, owner_user=owner,
                       seed="SEED", safe_summary="bgp-flap on rtr-1 (severity err)",
                       follow_up="another match")


# -- ntfy: public-topic safety ------------------------------------------------
async def test_ntfy_never_pushes_raw_body():
    http = FakeHTTP()
    d = NtfyDispatcher(http, default_url="https://n", default_token="k", default_topic="ring")
    res = await d.open(_ctx(body="root=hunter2 token=ABCDEF ip=10.0.0.9"), {"id": 1, "config": {}})
    assert res.ok
    sent = http.calls[0]["content"].decode()
    assert "hunter2" not in sent and "ABCDEF" not in sent   # raw body must NOT be on a public topic
    assert "bgp-flap" in sent                                # safe summary is fine


async def test_ntfy_target_config_overrides_topic():
    http = FakeHTTP()
    d = NtfyDispatcher(http, default_url="https://n", default_token="k", default_topic="default")
    await d.open(_ctx(), {"id": 1, "config": {"topic": "override"}})
    assert http.calls[0]["url"].endswith("/override")


# -- ntfy: SSRF guard (sec review B2) -----------------------------------------
async def test_ntfy_rejects_unlisted_url_host():
    http = FakeHTTP()
    d = NtfyDispatcher(http, default_url="https://ntfy.example.com", default_token="k")
    # a Write principal aims the target at an internal service
    res = await d.open(_ctx(), {"id": 1, "config": {"url": "http://127.0.0.1:8090", "topic": "x"}})
    assert not res.ok and "not allow-listed" in res.detail
    assert not http.calls                                    # NO request was made


async def test_ntfy_allows_explicitly_listed_url_host():
    http = FakeHTTP()
    d = NtfyDispatcher(http, default_url="https://ntfy.example.com", default_token="k",
                       allowed_hosts=["alt-ntfy.example.com"])
    res = await d.open(_ctx(), {"id": 1, "config": {"url": "https://alt-ntfy.example.com", "topic": "x"}})
    assert res.ok
    assert http.calls[0]["url"].startswith("https://alt-ntfy.example.com/")


# -- turnstone: blanket auto_approve is never honored (sec review M3) ----------
async def test_turnstone_ignores_blanket_auto_approve():
    http = FakeHTTP(FakeResp(200, {"ws_id": "ws-real"}))
    d = TurnstoneDispatcher(http, FakeAdmin(token="tok"), base_url="http://ts", default_owner="u")
    await d.open(_ctx(owner="u"), {"id": 1, "config": {"auto_approve": True}})
    assert "auto_approve" not in http.calls[0]["json"]       # blanket flag dropped


async def test_turnstone_honors_scoped_auto_approve_tools():
    http = FakeHTTP(FakeResp(200, {"ws_id": "ws-real"}))
    d = TurnstoneDispatcher(http, FakeAdmin(token="tok"), base_url="http://ts", default_owner="u")
    await d.open(_ctx(owner="u"), {"id": 1, "config": {"auto_approve_tools": "notify"}})
    assert http.calls[0]["json"]["auto_approve_tools"] == "notify"


# -- turnstone: fail-closed identity + owner resolution -----------------------
async def test_turnstone_fails_closed_without_owner():
    http = FakeHTTP()
    d = TurnstoneDispatcher(http, FakeAdmin(), base_url="http://ts", default_owner="")
    res = await d.open(_ctx(owner="", upn=""), {"id": 1, "config": {}})
    assert not res.ok and "fail-closed" in res.detail
    assert not http.calls                                    # never created a workstream


async def test_turnstone_opens_as_owner_and_returns_handle():
    http = FakeHTTP(FakeResp(200, {"ws_id": "ws-real"}))
    d = TurnstoneDispatcher(http, FakeAdmin(token="tok"), base_url="http://ts", default_owner="u-owner")
    res = await d.open(_ctx(owner="u-owner"), {"id": 1, "config": {}})
    assert res.ok and res.handle == "ws-real"
    assert http.calls[0]["headers"]["Authorization"] == "Bearer tok"
    assert "/v1/api/route/workstreams/new" in http.calls[0]["url"]
    # fail-closed default: no blanket auto_approve unless target opts in
    assert "auto_approve" not in http.calls[0]["json"]


async def test_turnstone_resolves_owner_from_upn():
    http = FakeHTTP()
    d = TurnstoneDispatcher(http, FakeAdmin(resolved="u-from-upn"), base_url="http://ts")
    res = await d.open(_ctx(owner="", upn="alice@example.com"), {"id": 1, "config": {}})
    assert res.ok                                            # resolved via admin, not fail-closed


async def test_turnstone_feed_reopens_when_ws_gone():
    http = FakeHTTP(FakeResp(410))
    d = TurnstoneDispatcher(http, FakeAdmin(), base_url="http://ts", default_owner="u")
    res = await d.feed(_ctx(owner="u"), {"id": 1, "config": {}}, "ws-old")
    assert res.gone


# -- coordinator: open / feed / throttle / fallback / rate --------------------
@pytest.fixture
def patch_db(monkeypatch):
    """Record DB writes; drive the incident lookup per test."""
    state = {"incident": None, "executed": []}

    async def fake_fetchone(pool, sql, params=()):
        if "alert_incidents" in sql:
            return state["incident"]
        return {"m": 0, "c": 0}

    async def fake_execute(pool, sql, params=()):
        state["executed"].append((sql.split()[0], sql))
        return {"id": 1}

    monkeypatch.setattr(inc_mod.db, "fetchone", fake_fetchone)
    monkeypatch.setattr(inc_mod.db, "execute", fake_execute)
    return state


def _reg(ntfy_http=None, ts_http=None, ts_ok=True):
    reg = {}
    if ntfy_http is not None:
        reg["ntfy"] = NtfyDispatcher(ntfy_http, default_url="https://n", default_token="k",
                                     default_topic="ring")
    if ts_http is not None:
        payload = {"ws_id": "ws-real"} if ts_ok else {}
        ts_http._resp = FakeResp(200 if ts_ok else 500, payload)
        reg["turnstone"] = TurnstoneDispatcher(ts_http, FakeAdmin(), base_url="http://ts",
                                               default_owner="u-owner")
    return reg


async def test_coordinator_opens_fresh_incident(patch_db):
    ts_http = FakeHTTP()
    coord = Coordinator(None, _reg(ts_http=ts_http), fallback_ntfy_topic="fb")
    disp = await coord.handle(_ctx(owner="u-owner"), {"id": 5, "type": "turnstone", "config": {}})
    assert disp == "opened"
    assert any("workstreams/new" in c["url"] for c in ts_http.calls)


async def test_coordinator_feeds_open_incident_within_ttl(patch_db):
    patch_db["incident"] = {"dedup_key": "1:5:rtr-1", "status": "open", "handle": "ws-real",
                            "owner_user": "u-owner",
                            "last_event_at": datetime.now(timezone.utc),
                            "last_fed_at": datetime.now(timezone.utc) - timedelta(hours=1)}
    ts_http = FakeHTTP()
    coord = Coordinator(None, _reg(ts_http=ts_http), feed_interval=60, fallback_ntfy_topic="fb")
    disp = await coord.handle(_ctx(owner="u-owner"), {"id": 5, "type": "turnstone", "config": {}})
    assert disp == "fed"
    assert any("/send" in c["url"] for c in ts_http.calls)


async def test_coordinator_throttles_recent_feed(patch_db):
    patch_db["incident"] = {"dedup_key": "1:5:rtr-1", "status": "open", "handle": "ws-real",
                            "owner_user": "u-owner",
                            "last_event_at": datetime.now(timezone.utc),
                            "last_fed_at": datetime.now(timezone.utc)}  # just fed -> throttle
    ts_http = FakeHTTP()
    coord = Coordinator(None, _reg(ts_http=ts_http), feed_interval=60, fallback_ntfy_topic="fb")
    disp = await coord.handle(_ctx(owner="u-owner"), {"id": 5, "type": "turnstone", "config": {}})
    assert disp == "throttled"
    assert not any("/send" in c["url"] for c in ts_http.calls)   # no send while throttled


async def test_coordinator_falls_back_to_ntfy_on_dispatch_failure(patch_db):
    ntfy_http, ts_http = FakeHTTP(), FakeHTTP()
    reg = _reg(ntfy_http=ntfy_http, ts_http=ts_http, ts_ok=False)
    # make the turnstone create fail
    ts_http._resp = FakeResp(500)
    coord = Coordinator(None, reg, fallback_ntfy_topic="fb")
    disp = await coord.handle(_ctx(owner="u-owner"), {"id": 5, "type": "turnstone", "config": {}})
    assert disp == "fallback"
    assert ntfy_http.calls                                       # a human was paged, not left blind


async def test_coordinator_rate_ceiling_suppresses_agent_open(patch_db):
    ntfy_http, ts_http = FakeHTTP(), FakeHTTP()
    reg = _reg(ntfy_http=ntfy_http, ts_http=ts_http)
    coord = Coordinator(None, reg, rate_ceiling=0, fallback_ntfy_topic="fb")   # ceiling hit immediately
    disp = await coord.handle(_ctx(owner="u-owner"), {"id": 5, "type": "turnstone", "config": {}})
    assert disp == "rate_limited"
    assert not any("workstreams/new" in c["url"] for c in ts_http.calls)       # no summon
    assert ntfy_http.calls                                                     # but a push heads-up


async def test_coordinator_unknown_type_falls_back(patch_db):
    ntfy_http = FakeHTTP()
    coord = Coordinator(None, _reg(ntfy_http=ntfy_http), fallback_ntfy_topic="fb")
    disp = await coord.handle(_ctx(), {"id": 9, "type": "webhook-template", "config": {}})
    assert disp == "fallback"
    assert ntfy_http.calls
