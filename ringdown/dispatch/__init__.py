"""ringdown.dispatch — pluggable target/dispatcher registry.

A registry maps a target ``type`` -> a :class:`Dispatcher` instance. Adding a
new responder channel is: implement a Dispatcher subclass, register it here.
The router/coordinator never learns a concrete type — it looks one up by the
target row's ``type`` and calls ``open``/``feed``.
"""
from __future__ import annotations

from ..obo import TurnstoneAdmin
from .base import Dispatcher, DispatchResult, FireContext
from .ntfy import NtfyDispatcher
from .turnstone import TurnstoneDispatcher

__all__ = ["Dispatcher", "DispatchResult", "FireContext", "build_registry", "Registry"]

Registry = dict[str, Dispatcher]


def build_registry(http, *, admin: TurnstoneAdmin | None = None, turnstone_url: str = "",
                   default_owner: str = "", default_project: str = "", ntfy_url: str = "",
                   ntfy_token: str = "", ntfy_topic: str = "ringdown", ntfy_allowed_hosts=None) -> Registry:
    """Construct the enabled dispatchers from config. A type is present only if
    its prerequisites are configured (so a missing admin token simply means the
    ``turnstone`` type is absent, and rules bound to it degrade to fallback)."""
    reg: Registry = {}
    if ntfy_url and ntfy_token:
        reg["ntfy"] = NtfyDispatcher(http, default_url=ntfy_url, default_token=ntfy_token,
                                     default_topic=ntfy_topic, allowed_hosts=ntfy_allowed_hosts)
    if admin is not None and admin.enabled:
        reg["turnstone"] = TurnstoneDispatcher(http, admin, base_url=turnstone_url,
                                               default_owner=default_owner,
                                               default_project=default_project)
    return reg
