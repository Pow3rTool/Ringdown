"""Owner-resolution regression tests (sec review B4).

A real UPN must resolve to the *creator's* Turnstone user_id, not silently fall
through to the shared default_owner — otherwise run-as-owner collapses to one
identity and the per-user least-privilege model is defeated.
"""
import time

import pytest

from ringdown.obo import TurnstoneAdmin


def _admin_with_users(users: dict[str, str]) -> TurnstoneAdmin:
    a = TurnstoneAdmin("https://ts.example.com", "admin-tok")
    a._users = dict(users)
    a._users_at = time.time()  # keep cache fresh so no HTTP refresh is attempted
    return a


async def test_upn_resolves_to_local_part_username():
    # Turnstone stores username as the UPN local part (Ringdown prototype convention).
    a = _admin_with_users({"alice": "u-alice", "bob": "u-bob"})
    assert await a.resolve_owner("alice@corp.example.com") == "u-alice"


async def test_upn_resolves_when_username_is_full_upn():
    # Fallback: some deployments store the full UPN as username.
    a = _admin_with_users({"alice@corp.example.com": "u-alice"})
    assert await a.resolve_owner("alice@corp.example.com") == "u-alice"


async def test_unknown_upn_returns_empty_not_wrong_owner():
    a = _admin_with_users({"alice": "u-alice"})
    assert await a.resolve_owner("mallory@corp.example.com") == ""


async def test_blank_upn_returns_empty():
    a = _admin_with_users({"alice": "u-alice"})
    assert await a.resolve_owner("") == ""
    assert await a.resolve_owner(None) == ""
