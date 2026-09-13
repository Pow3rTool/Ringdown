"""ringdown.dispatch.turnstone — summon an agent, run-as-owner (OBO).

The reference stateful/authenticated dispatcher. On a fresh
incident it opens ONE Turnstone workstream **as the hook's owner** (via the
owner-OBO bridge in :mod:`ringdown.obo`) seeded with the compact triage context;
repeat matches feed that same workstream instead of spawning new ones. A
metadata-only lifecycle read confirms closure; send 404/410 alone is not proof.

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
from dataclasses import replace

from ..obo import TurnstoneAdmin
from .base import Dispatcher, DispatchResult, FireContext


class TurnstoneDispatcher(Dispatcher):
    type = "turnstone"
    stateful = True

    def __init__(self, http, admin: TurnstoneAdmin, *, base_url: str,
                 default_owner: str = "", default_project: str = ""):
        self._http = http
        self._admin = admin
        self._base = base_url.rstrip("/")
        self._default_owner = default_owner
        self._default_project = default_project

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
            return DispatchResult(ok=False, detail="no resolvable owner for the rule (fail-closed)",
                                  meta={"retry_create": True})
        cfg = target.get("config") or {}
        try:
            token = await self._admin.token_for(owner)
        except Exception as e:
            return DispatchResult(ok=False, detail=f"owner-token mint failed ({type(e).__name__})",
                                  meta={"retry_create": True})

        ws_id = ctx.request_id or secrets.token_hex(16)
        # Send the seed separately, after durably recording the handle. A
        # refused/ambiguous send must not spawn another chat.
        body: dict = {"name": self._ws_name(ctx), "kind": "interactive"}
        # Fail-closed defaults: blanket auto-approve is NEVER honored (it's refused
        # at target registration too — defense in depth against a directly-edited
        # DB row). Only a scoped tool list may relax the human-approval gate.
        if cfg.get("auto_approve_tools"):
            body["auto_approve_tools"] = str(cfg["auto_approve_tools"])
        if cfg.get("skill"):
            body["skill"] = str(cfg["skill"])
        if cfg.get("model"):
            body["model"] = str(cfg["model"])
        # Project attach, most-specific wins: the rule's own project_id, else the
        # target's, else the deployment-wide default (config.TURNSTONE_DEFAULT_PROJECT).
        # Turnstone re-validates that the run-as OWNER is a member
        # (ensure_project_attachable) and silently drops the id otherwise — a
        # projectless create is then refused under server.require_project and we
        # fall back to ntfy. So a mis-assigned project degrades to a push; it
        # never lands a chat in the wrong tenant.
        project_id = (str(ctx.rule.get("project_id") or "").strip()
                      or str(target.get("project_id") or "").strip()
                      or str(self._default_project or "").strip())
        if project_id:
            body["project_id"] = project_id
        try:
            r = await self._http.post(
                f"{self._base}/v1/api/route/workstreams/new?ws_id={ws_id}",
                headers={"Authorization": f"Bearer {token}"}, json=body)
            if r.status_code == 409:
                return DispatchResult(ok=False, handle=ws_id, detail="create id already exists; reconcile",
                                      meta={"ambiguous": True})
            if 400 <= r.status_code < 500:
                return DispatchResult(ok=False, handle=ws_id,
                                      detail=f"create refused (HTTP {r.status_code})",
                                      meta={"retry_create": True})
            r.raise_for_status()
        except Exception as e:
            return DispatchResult(ok=False, handle=ws_id,
                                  detail=f"create outcome unknown ({type(e).__name__}); reconcile",
                                  meta={"ambiguous": True})
        ws_id = (r.json() or {}).get("ws_id", ws_id) or ws_id
        return DispatchResult(ok=True, handle=ws_id, detail=f"opened ws {ws_id} as {owner}",
                              meta={"project_id": project_id})

    async def feed(self, ctx: FireContext, target: dict, handle: str) -> DispatchResult:
        owner = await self._owner(ctx)
        if not owner:
            return DispatchResult(ok=False, detail="no resolvable owner for the rule (fail-closed)")
        try:
            token = await self._admin.token_for(owner)
            r = await self._http.post(
                f"{self._base}/v1/api/route/workstreams/{handle}/send",
                headers={"Authorization": f"Bearer {token}"},
                json={"message": ctx.follow_up or ctx.seed,
                      **({"client_send_id": ctx.delivery_id} if ctx.delivery_id else {})})
        except Exception as e:
            return DispatchResult(ok=False, detail=f"feed outcome unknown ({type(e).__name__})")
        if r.status_code in (404, 410):
            return DispatchResult(ok=False, gone=True, detail=f"ws {handle} gone ({r.status_code})")
        try:
            r.raise_for_status()
        except Exception:
            return DispatchResult(ok=False, detail=f"feed refused (HTTP {r.status_code})")
        status = (r.json() or {}).get("status")
        if status not in ("ok", "queued"):
            return DispatchResult(ok=False, handle=handle,
                                  detail=f"send not accepted ({status or 'unknown response'})",
                                  meta={"send_status": status})
        return DispatchResult(ok=True, handle=handle, detail=f"send accepted ({status})",
                              meta={"send_status": status, "queued_messages": None})

    async def prepare(self, ctx: FireContext, target: dict) -> FireContext:
        owner = await self._owner(ctx)
        if not owner:
            raise ValueError("no resolvable owner for the rule (fail-closed)")
        project = (ctx.rule.get("project_id") or target.get("project_id")
                   or self._default_project or "")
        return replace(ctx, owner_user=owner, rule={**ctx.rule, "project_id": project})

    async def inspect(self, ctx: FireContext, target: dict, handle: str) -> DispatchResult:
        # NOT /route/.../detail: that endpoint can rehydrate a CLOSED chat!
        # This metadata-only endpoint needs admin.cluster.inspect on the owner
        # token. 403/404 are UNKNOWN (404 can mask private-project tenancy).
        try:
            owner = await self._owner(ctx)
            if not owner:
                return DispatchResult(ok=False, detail="no inspection identity")
            token = await self._admin.token_for(owner)
            r = await self._http.get(
                f"{self._base}/v1/api/cluster/ws/{handle}/detail?limit=0",
                headers={"Authorization": f"Bearer {token}"})
            if r.status_code != 200:
                return DispatchResult(ok=False, handle=handle,
                                      detail=f"lifecycle unknown (HTTP {r.status_code})")
            data = r.json()
            persisted = data.get("persisted") or {}
            live = data.get("live") or {}
            if persisted.get("user_id") != owner:
                return DispatchResult(ok=False, handle=handle, detail="workstream owner mismatch")
            if persisted.get("ws_id") != handle:
                return DispatchResult(ok=False, handle=handle, detail="workstream identity mismatch")
            state = live.get("state") or persisted.get("state")
            if not state:
                return DispatchResult(ok=False, handle=handle, detail="lifecycle state missing")
            return DispatchResult(ok=True, handle=handle, gone=state in ("closed", "deleted"),
                                  detail=f"workstream {state}", meta={
                                      "state": state, "live": bool(live),
                                      "project_id": persisted.get("project_id") or "",
                                      "closed_at": persisted.get("updated") if state in ("closed", "deleted") else None,
                                      "queued_messages": None})
        except Exception as e:
            return DispatchResult(ok=False, handle=handle,
                                  detail=f"lifecycle unknown ({type(e).__name__})")

    @staticmethod
    def _ws_name(ctx: FireContext) -> str:
        import re
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", ctx.rule.get("name") or "")[:32]
        ev = ctx.event
        ts = ev.get("ts")
        iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(ts, "strftime") else "?"
        return f"ringdown/{ev.get('source')}/{ev.get('severity_text') or '?'}/{slug}/{iso}"
