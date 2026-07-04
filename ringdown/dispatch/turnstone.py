"""ringdown.dispatch.turnstone — summon an agent, run-as-owner (OBO).

The reference stateful/authenticated dispatcher. On a fresh
incident it opens ONE Turnstone workstream **as the hook's owner** (via the
owner-OBO bridge in :mod:`ringdown.obo`) seeded with the compact triage context;
repeat matches feed that same workstream instead of spawning new ones. When the
workstream is gone (404/410) it reports `gone` so the coordinator reopens.

Security posture (fail-closed — this summons an agent that can act):
  * Runs as the OWNER's identity, so every action is attributable + least-priv.
  * Tool auto-approval is OFF by default. Destructive/effectful tools hit
    Turnstone's human-approval gate. An operator may widen approval per target
    via ``config.auto_approve_tools`` (e.g. "notify") — never blanket-approve
    unless a target's owner explicitly opts in via ``config.auto_approve``.
  * Confused-deputy note: the workstream holds the owner's OBO token.
    Ringdown creates it owned by the owner (single-writer by construction); the
    read-only-for-non-owners project ACL is an UPSTREAM Turnstone dependency and
    is NOT yet enforced there — do not treat project membership as send rights
    until Turnstone ships that gate.
"""
from __future__ import annotations

import secrets

from ..obo import TurnstoneAdmin
from .base import Dispatcher, DispatchResult, FireContext


class TurnstoneDispatcher(Dispatcher):
    type = "turnstone"
    stateful = True

    def __init__(self, http, admin: TurnstoneAdmin, *, base_url: str,
                 default_owner: str = ""):
        self._http = http
        self._admin = admin
        self._base = base_url.rstrip("/")
        self._default_owner = default_owner

    async def _owner(self, ctx: FireContext) -> str:
        """Resolve the run-as identity: the rule's stored owner_user, else the
        creator's UPN resolved to a turnstone user_id, else the default owner."""
        if ctx.owner_user:
            return ctx.owner_user
        upn = ctx.rule.get("created_by_upn") or ""
        if upn:
            resolved = await self._admin.resolve_owner(upn)
            if resolved:
                return resolved
        return self._default_owner

    async def open(self, ctx: FireContext, target: dict) -> DispatchResult:
        owner = await self._owner(ctx)
        if not owner:
            # No resolvable identity -> we will NOT run as a wrong/blank identity.
            return DispatchResult(ok=False, detail="no resolvable owner for the rule (fail-closed)")
        cfg = target.get("config") or {}
        try:
            token = await self._admin.token_for(owner)
        except Exception as e:
            return DispatchResult(ok=False, detail=f"owner-token mint failed: {type(e).__name__}: {str(e)[:160]}")

        ws_id = secrets.token_hex(16)
        body: dict = {"name": self._ws_name(ctx), "kind": "interactive",
                      "initial_message": ctx.seed}
        # Fail-closed defaults: blanket auto-approve is NEVER honored (it's refused
        # at target registration too — defense in depth against a directly-edited
        # DB row). Only a scoped tool list may relax the human-approval gate.
        if cfg.get("auto_approve_tools"):
            body["auto_approve_tools"] = str(cfg["auto_approve_tools"])
        if cfg.get("skill"):
            body["skill"] = str(cfg["skill"])
        if cfg.get("model"):
            body["model"] = str(cfg["model"])
        # NOTE: project attach is intentionally NOT sent — Turnstone's create
        # route does not yet accept project_id. rule.project_id
        # is carried for when that route lands.
        try:
            r = await self._http.post(
                f"{self._base}/v1/api/route/workstreams/new?ws_id={ws_id}",
                headers={"Authorization": f"Bearer {token}"}, json=body)
            r.raise_for_status()
        except Exception as e:
            return DispatchResult(ok=False, detail=f"create failed: {type(e).__name__}: {str(e)[:160]}")
        ws_id = (r.json() or {}).get("ws_id", ws_id) or ws_id
        return DispatchResult(ok=True, handle=ws_id, detail=f"opened ws {ws_id} as {owner}",
                              meta={"project_id": ctx.rule.get("project_id") or ""})

    async def feed(self, ctx: FireContext, target: dict, handle: str) -> DispatchResult:
        owner = await self._owner(ctx)
        if not owner:
            return DispatchResult(ok=False, detail="no resolvable owner for the rule (fail-closed)")
        try:
            token = await self._admin.token_for(owner)
            r = await self._http.post(
                f"{self._base}/v1/api/route/workstreams/{handle}/send",
                headers={"Authorization": f"Bearer {token}"},
                json={"message": ctx.follow_up or ctx.seed})
        except Exception as e:
            return DispatchResult(ok=False, detail=f"feed failed: {type(e).__name__}: {str(e)[:160]}")
        if r.status_code in (404, 410):
            return DispatchResult(ok=False, gone=True, detail=f"ws {handle} gone ({r.status_code})")
        try:
            r.raise_for_status()
        except Exception as e:
            return DispatchResult(ok=False, detail=f"feed failed: {type(e).__name__}: {str(e)[:160]}")
        return DispatchResult(ok=True, handle=handle, detail=f"fed ws {handle}")

    @staticmethod
    def _ws_name(ctx: FireContext) -> str:
        import re
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", ctx.rule.get("name") or "")[:32]
        ev = ctx.event
        ts = ev.get("ts")
        iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(ts, "strftime") else "?"
        return f"ringdown/{ev.get('source')}/{ev.get('severity_text') or '?'}/{slug}/{iso}"
