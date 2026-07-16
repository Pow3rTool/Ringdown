"""Router matching + fan-out + coalesce-per-target + stop_on_match.

The router turns matched rules into dispatch calls; the coordinator (faked here)
owns state. We assert the routing decisions: gating (severity/glob), fan-out to
multiple targets, coalescing one event across rules that share a target, and the
terminal-stop knob.

Requires the runtime deps (httpx/psycopg) — run under the venv.
"""
from __future__ import annotations

import re

from ringdown.router import Router


class FakeRuleset:
    def __init__(self, rules):
        self._rules = rules

    @property
    def rules(self):
        return self._rules


class FakeCoord:
    def __init__(self):
        self.dispatched = []   # (rule_id, target_id)

    async def handle(self, ctx, target, dedup_source=None):
        self.dispatched.append((ctx.rule["id"], target["id"]))
        return "opened"


def _rule(rid, pattern, targets, *, glob="", min_sev=0, order=100, stop=False):
    return {"id": rid, "name": f"r{rid}", "rx": re.compile(pattern), "instructions": "",
            "glob": glob, "min_sev": min_sev, "rule_order": order, "stop_on_match": stop,
            "owner_user": "u", "project_id": "", "created_by": "o", "created_by_upn": "u@x",
            "targets": [{"id": t, "name": f"t{t}", "type": "ntfy", "config": {}} for t in targets]}


def _event(body, source="rtr-1", sev=17):
    return {"source": source, "severity": sev, "severity_text": "err", "program": "%X",
            "body": body, "raw": body, "ts": None}


async def _run(rules, event):
    coord = FakeCoord()
    r = Router(FakeRuleset(rules), coord)
    r.consider([event])
    await r.drain()
    return coord.dispatched


async def test_single_match_dispatches_its_target():
    got = await _run([_rule(1, "flap", [10])], _event("link flap detected"))
    assert got == [(1, 10)]


async def test_no_match_no_dispatch():
    got = await _run([_rule(1, "flap", [10])], _event("all healthy"))
    assert got == []


async def test_severity_floor_gates():
    got = await _run([_rule(1, "flap", [10], min_sev=18)], _event("flap", sev=13))
    assert got == []


async def test_source_glob_gates():
    got = await _run([_rule(1, "flap", [10], glob="sw-*")], _event("flap", source="rtr-1"))
    assert got == []


async def test_fan_out_to_multiple_targets():
    got = await _run([_rule(1, "flap", [10, 11])], _event("flap"))
    assert set(got) == {(1, 10), (1, 11)}


async def test_coalesce_shared_target_across_rules():
    # rule1 -> t10 ; rule2 -> t10, t11. One event matches both: t10 fires ONCE
    # (first rule wins), t11 still fires. No double-page to the same target.
    rules = [_rule(1, "flap", [10], order=1), _rule(2, "flap", [10, 11], order=2)]
    got = await _run(rules, _event("flap"))
    assert got.count((1, 10)) == 1
    assert (2, 10) not in got                 # coalesced away
    assert (2, 11) in got                      # different target still fires
    assert len(got) == 2


async def test_stop_on_match_halts_lower_rules():
    rules = [_rule(1, "flap", [10], order=1, stop=True), _rule(2, "flap", [11], order=2)]
    got = await _run(rules, _event("flap"))
    assert got == [(1, 10)]                     # rule2 never evaluated


async def test_silent_block_stops_without_dispatch():
    # An unbound stop_on_match rule is an allowlist "block quick": it matches, halts
    # lower-priority rules, and dispatches to NOBODY (zero-notification suppression).
    rules = [_rule(1, "allow", [], order=1, stop=True), _rule(2, "allow", [11], order=2)]
    got = await _run(rules, _event("allow this"))
    assert got == []                            # rule1 blocked silently; rule2 never evaluated


async def test_unbound_nonstop_rule_is_noop_not_terminal():
    # An unbound rule WITHOUT stop_on_match dispatches nothing but does NOT halt the
    # router; a lower-priority bound rule still fires. (The ruleset compiler drops such
    # a rule entirely; the router must also neither crash nor block on it.)
    rules = [_rule(1, "allow", [], order=1, stop=False), _rule(2, "allow", [11], order=2)]
    got = await _run(rules, _event("allow this"))
    assert got == [(2, 11)]
