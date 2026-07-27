"""Ruleset compilation tests, including the linear-time RE2 boundary."""
from __future__ import annotations

from ringdown import ruleset as ruleset_module
from ringdown.ruleset import Ruleset


def _rule(rule_id: int, pattern: str, *, stop: bool = True):
    return {
        "id": rule_id,
        "name": f"rule-{rule_id}",
        "pattern": pattern,
        "instructions": None,
        "source_glob": None,
        "min_severity": None,
        "rule_order": 100,
        "stop_on_match": stop,
        "owner_user": None,
        "project_id": None,
        "created_by": "owner",
        "created_by_upn": "owner@example.test",
    }


async def test_ruleset_compiles_re2_and_skips_unsupported_direct_db_pattern(monkeypatch):
    responses = iter([
        [
            _rule(1, r"Accepted (publickey|password) for"),
            _rule(2, r"foo(?=bar)"),  # lookahead is unsupported by RE2
            _rule(3, r"unbound nonterminal", stop=False),
        ],
        [],  # target bindings
    ])

    async def fake_fetch(_pool, _sql, _params=()):
        return next(responses)

    monkeypatch.setattr(ruleset_module.db, "fetch", fake_fetch)
    ruleset = Ruleset(pool=None)
    await ruleset.reload()

    assert len(ruleset) == 1
    assert ruleset.rules[0]["id"] == 1
    assert ruleset.rules[0]["rx"].search("sshd Accepted publickey for root")
