"""ringdown.ruleset — the in-memory compiled ruleset (live-refreshed).

The collector holds the enabled regex (L1) rules + their target bindings HOT in
memory and refreshes them ONLY on a Postgres ``rules_changed`` NOTIFY — never a
per-line DB read. The ruleset is small, so a full reload on any
change is simplest and correct; the NOTIFY payload is available for a targeted
refetch later if it ever isn't.
"""
from __future__ import annotations

import re

from . import db


class Ruleset:
    def __init__(self, pool):
        self._pool = pool
        self._rules: list[dict] = []   # compiled L1 rules, each with its bound targets

    @property
    def rules(self) -> list[dict]:
        return self._rules

    def __len__(self) -> int:
        return len(self._rules)

    async def reload(self) -> None:
        """Rebuild the compiled L1 ruleset + target bindings from the DB."""
        rows = await db.fetch(self._pool,
            "SELECT id, name, pattern, instructions, source_glob, min_severity, rule_order, "
            "stop_on_match, owner_user, project_id, created_by, created_by_upn "
            "FROM alert_rules WHERE enabled AND kind = 'regex' ORDER BY rule_order, id")
        # target bindings for all rules in one query
        binds = await db.fetch(self._pool,
            "SELECT rt.rule_id, rt.target_order, rt.stop_on_match AS bind_stop, "
            "t.id, t.name, t.type, t.config, t.identity_policy, t.owner_oid "
            "FROM rule_targets rt JOIN targets t ON t.id = rt.target_id "
            "ORDER BY rt.target_order, t.id")
        by_rule: dict = {}
        for b in binds:
            by_rule.setdefault(b["rule_id"], []).append({
                "id": b["id"], "name": b["name"], "type": b["type"], "config": b["config"],
                "identity_policy": b["identity_policy"], "owner_oid": b["owner_oid"],
                "target_order": b["target_order"], "bind_stop": b["bind_stop"],
            })
        compiled = []
        for r in rows:
            try:
                rx = re.compile(r["pattern"])
            except re.error:
                continue  # a bad regex is skipped, not fatal (MCP validates on write)
            targets = by_rule.get(r["id"], [])
            if not targets:
                continue  # an unbound rule can't fire anywhere — skip it
            compiled.append({
                "id": r["id"], "name": r["name"], "rx": rx,
                "instructions": r["instructions"], "glob": r["source_glob"],
                "min_sev": r["min_severity"] or 0, "rule_order": r["rule_order"],
                "stop_on_match": r["stop_on_match"], "owner_user": r["owner_user"],
                "project_id": r["project_id"], "created_by": r["created_by"],
                "created_by_upn": r["created_by_upn"], "targets": targets,
            })
        self._rules = compiled
