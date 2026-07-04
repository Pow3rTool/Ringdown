"""ringdown.dispatch.base — the Dispatcher plugin contract.

A Dispatcher is *how* to reach a responder, decoupled from any rule.
It is deliberately thin: `open` a handle for a fresh incident, `feed` an
existing one, `aclose` to release resources. All state (dedup, reuse-TTL,
throttle, fallback) lives in the coordinator (`ringdown.incidents`), NOT here —
a plugin only knows how to talk to its channel.

The interface is designed so a wildly different agent platform can be added
later as a new plugin with no change to the router/coordinator: it sees only
`open`/`feed` returning an opaque `handle`.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field


@dataclass
class FireContext:
    """Everything a dispatcher needs about one firing, channel-agnostic."""
    rule: dict                       # alert_rules row (id, name, kind, pattern, instructions, project_id, …)
    event: dict                      # normalized event (source, severity, severity_text, program, body, ts, …)
    owner_user: str = ""             # turnstone user_id to RUN AS (run-as-owner); "" if not resolved
    seed: str = ""                   # compact agent seed (built by the router; token-capped)
    safe_summary: str = ""           # public-safe one-liner — the ONLY thing safe for a public ntfy topic
    follow_up: str = ""              # terse "another match" line for feeds
    is_repeat: bool = False          # coordinator's open-vs-feed decision (informational)


@dataclass
class DispatchResult:
    ok: bool
    handle: str = ""                 # opaque handle to persist (turnstone ws_id; "" for stateless)
    detail: str = ""                 # human-readable note for audit / fallback message
    gone: bool = False               # the fed handle no longer exists -> coordinator should reopen
    meta: dict = field(default_factory=dict)


class Dispatcher(abc.ABC):
    """Base class for a target type. Subclasses set `type` + `stateful`."""

    type: str = ""
    #: stateful dispatchers hold a handle that can be fed (turnstone workstream);
    #: stateless ones (ntfy) re-push on every fire and never go "gone".
    stateful: bool = False

    @abc.abstractmethod
    async def open(self, ctx: FireContext, target: dict) -> DispatchResult:
        """Start a fresh incident on this channel; return a handle to persist."""

    async def feed(self, ctx: FireContext, target: dict, handle: str) -> DispatchResult:
        """Fold a repeat match into an existing handle. Default: re-open (stateless)."""
        return await self.open(ctx, target)

    async def aclose(self) -> None:
        """Release resources (HTTP clients, etc.). Optional."""
        return None
