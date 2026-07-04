"""ringdown.obo — the Turnstone owner-OBO bridge.

A fired hook must run **as the human who created it** (run-as-owner): every
agent action then traces to a real person and is bounded by that person's own
authorization. The user is offline when the hook fires, so Ringdown
can't drive an interactive OBO flow.

This module implements the **proven interim bridge** (validated by the Ringdown prototype, zero Turnstone-source change): a Turnstone *admin* token mints a short-
lived, scoped, per-owner token via ``POST /v1/api/admin/users/{uid}/tokens``.
Ringdown authenticates onward AS the owner with that token — so Turnstone sees
``sub = owner`` and the existing create/send routes just work.

  Admin token = the AUTHORITY to mint. The minted per-user token = the
  ACTING IDENTITY. Ringdown never holds the admin token beyond this module and
  never lets it become the acting identity of a workstream.

The aspirational end-state is Turnstone holding each user's
``offline_access`` refresh token and doing real deferred OBO; when that lands,
only this module changes — the dispatcher above it is unaffected.
"""
from __future__ import annotations

import re
import time

import httpx

# Turnstone derives a user's `username` from the OIDC `preferred_username` claim
# by deleting every character outside this set (see turnstone.core.oidc
# `_derive_username` / `_USERNAME_SAFE_RE`). Notably that strips the `@`, so
# `alice@example.com` becomes `aliceexample.com`. We
# mirror the SAME transform when mapping a rule owner's UPN -> turnstone user, so
# the outbound adapter resolves against the identifier Turnstone actually stores
# rather than guessing. (Proper fix — match on a stable OAuth claim, e.g. Azure
# `oid` — is queued; blocked until Turnstone captures one: it currently keys on a
# per-app pairwise `sub` and stores no email.)
_TS_USERNAME_UNSAFE = re.compile(r"[^a-zA-Z0-9._-]")


class TurnstoneAdmin:
    """Admin-scoped helper: resolve owners and mint per-owner run-as tokens.

    Token minting is cached per user_id (tokens are short-lived; re-mint before
    expiry). The admin token is read once and lives only inside this object.
    """

    def __init__(self, base_url: str, admin_token: str, *, token_ttl_hours: float = 20.0,
                 token_scopes: str = "read,write", http: httpx.AsyncClient | None = None):
        self.base_url = base_url.rstrip("/")
        self._admin = admin_token
        self._ttl = token_ttl_hours * 3600
        self._scopes = token_scopes
        self._http = http or httpx.AsyncClient(timeout=httpx.Timeout(15.0, read=30.0))
        self._owns_http = http is None
        self._tokens: dict[str, tuple[str, float]] = {}   # user_id -> (raw_token, minted_at)
        self._users: dict[str, str] = {}                  # username -> user_id
        self._users_at = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self._admin)

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # -- owner resolution -------------------------------------------------------
    async def refresh_users(self) -> None:
        """Cache username -> user_id from the admin users list.

        Turnstone's convention (from the Ringdown prototype): ``users.username`` == the UPN
        without its ``@domain``. Callers pass a UPN; we strip and look up.
        """
        r = await self._http.get(f"{self.base_url}/v1/api/admin/users",
                                 headers={"Authorization": f"Bearer {self._admin}"})
        r.raise_for_status()
        self._users = {u.get("username", ""): u.get("user_id", "")
                       for u in r.json().get("users", []) if u.get("username")}
        self._users_at = time.time()

    async def resolve_owner(self, upn: str) -> str:
        """UPN -> turnstone user_id, or "" if unknown. Refreshes the cache lazily.

        Turnstone stores ``username`` as the OIDC ``preferred_username`` with every
        char outside ``[A-Za-z0-9._-]`` deleted (see ``_TS_USERNAME_UNSAFE``), so the
        primary candidate mirrors that transform of the full UPN
        (``alice@example.com`` -> ``aliceexample.com``).
        The local-part and raw UPN are kept as fallbacks for other provisioning
        conventions. A miss here collapses run-as-owner to the shared default_owner
        (or fails closed), so it must not miss on a real UPN.
        """
        upn = (upn or "").strip()
        if not upn:
            return ""
        local = upn.split("@", 1)[0]
        derived = _TS_USERNAME_UNSAFE.sub("", upn)[:64]   # mirrors turnstone _derive_username
        candidates = [derived, local, upn]
        if not any(c in self._users for c in candidates) or (time.time() - self._users_at) > 300:
            try:
                await self.refresh_users()
            except Exception:
                pass  # fall through to whatever is cached
        for c in candidates:
            uid = self._users.get(c)
            if uid:
                return uid
        return ""

    # -- per-owner token mint ---------------------------------------------------
    async def token_for(self, user_id: str) -> str:
        """A short-lived token that authenticates AS ``user_id`` (cached)."""
        cached = self._tokens.get(user_id)
        if cached and (time.time() - cached[1]) < self._ttl:
            return cached[0]
        r = await self._http.post(
            f"{self.base_url}/v1/api/admin/users/{user_id}/tokens",
            headers={"Authorization": f"Bearer {self._admin}"},
            json={"name": "ringdown-runas", "scopes": self._scopes, "expires_days": 1})
        r.raise_for_status()
        tok = r.json()["token"]
        self._tokens[user_id] = (tok, time.time())
        return tok
