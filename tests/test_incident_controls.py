"""MCP configuration and read authorization for incident delivery."""
from types import SimpleNamespace

import pytest

from ringdown import config

EXAMPLE_RULE_ID = 1001


@pytest.fixture
def server(monkeypatch):
    # Control-plane unit tests don't connect to a DB or require live secrets.
    monkeypatch.setattr(config, "validate_mcp", lambda: None)
    from ringdown import mcp_server
    return mcp_server


@pytest.fixture
def controls(monkeypatch, server):
    writes = []
    monkeypatch.setattr(server, "_auth", lambda ctx: SimpleNamespace(oid="owner", upn="u", appid="app"))
    monkeypatch.setattr(server, "_authz", lambda ident, write: (True, None))
    monkeypatch.setattr(server, "_is_admin", lambda ident: True)

    async def owner(rule_id):
        return {"created_by": "owner", "created_by_bot": "app", "name": "ssh"}

    async def execute(sql, params):
        writes.append((sql, params))
        return {"id": EXAMPLE_RULE_ID, "name": "ssh"}

    async def audit(*args):
        pass

    monkeypatch.setattr(server, "_load_rule_owner", owner)
    monkeypatch.setattr(server, "_exec", execute)
    monkeypatch.setattr(server, "_audit", audit)
    return writes


async def test_group_edit_is_explicit_and_validated(controls, server):
    await server.update_alert(None, EXAMPLE_RULE_ID, group_by="rule")
    assert controls[0][1] == ["rule", EXAMPLE_RULE_ID]
    assert "group_by = %s" in controls[0][0]
    controls.clear()
    result = await server.update_alert(None, EXAMPLE_RULE_ID, group_by="everything")
    assert "group_by must be" in result and not controls


async def test_register_defaults_to_host_and_rejects_invalid_group(controls, server):
    from inspect import signature
    assert signature(server.register_alert).parameters["group_by"].default == "host"
    result = await server.register_alert(None, "ssh", "regex", "login", group_by="bad")
    assert "group_by must be" in result and not controls


async def test_dispatch_status_requires_read_access(monkeypatch, server):
    monkeypatch.setattr(server, "_auth", lambda ctx: None)
    assert "unauthenticated" in await server.dispatch_status(None)
    monkeypatch.setattr(server, "_auth", lambda ctx: object())
    monkeypatch.setattr(server, "_authz", lambda ident, write: (False, "denied"))
    assert "denied" in await server.dispatch_status(None)
