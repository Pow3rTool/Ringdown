"""ringdown.dispatch.ntfy — fire-and-forget human push (public-topic-safe).

⚠️  ntfy topics are PUBLIC — anyone who knows the topic can read it. This
dispatcher is safe BY CONSTRUCTION: it pushes only rule name + source +
severity + the LLM-sanitized ``safe_summary``. It NEVER puts a raw log line
(``event.body``/``raw``) on the wire — those may carry IPs, usernames, tokens.
Sensitive detail stays in Ringdown / the private workstream.

Stateless: there is no handle to feed, so `feed` re-pushes a terse "still
happening" line; the coordinator throttles repeat feeds so a flap doesn't spam.
"""
from __future__ import annotations

from urllib.parse import urlparse

from .base import Dispatcher, DispatchResult, FireContext


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


class NtfyDispatcher(Dispatcher):
    type = "ntfy"
    stateful = False

    def __init__(self, http, *, default_url: str = "", default_token: str = "",
                 default_topic: str = "ringdown", allowed_hosts=None):
        self._http = http
        self._url = default_url.rstrip("/")
        self._token = default_token
        self._topic = default_topic
        # SSRF allow-list: the configured host is always allowed; anything else a
        # per-target `url` points at must be explicitly allow-listed. This keeps a
        # Write principal from turning the collector into an internal-request proxy.
        self._allowed = {_host(self._url)} | {h.lower() for h in (allowed_hosts or [])}
        self._allowed.discard("")

    def url_allowed(self, url: str) -> bool:
        return _host(url) in self._allowed

    def _cfg(self, target: dict) -> tuple[str, str, str]:
        c = target.get("config") or {}
        url = (c.get("url") or self._url).rstrip("/")
        token = c.get("token") or self._token
        topic = c.get("topic") or self._topic
        return url, token, topic

    async def _push(self, target: dict, title: str, message: str, *,
                    priority: str = "default", tags=None) -> DispatchResult:
        url, token, topic = self._cfg(target)
        if not (url and topic):
            return DispatchResult(ok=False, detail="ntfy target missing url/topic")
        if not self.url_allowed(url):
            # SSRF guard: refuse to POST to a host that isn't the configured ntfy
            # server or an explicitly allow-listed one (RINGDOWN_NTFY_ALLOWED_HOSTS).
            return DispatchResult(ok=False, detail=f"ntfy url host not allow-listed: {_host(url)!r}")
        if token and urlparse(url).scheme != "https":
            # Don't ride the write-token over plaintext (a per-target `url` could
            # downgrade https->http). The message body is public-safe either way;
            # this only protects the bearer. Token-less public topics may use http.
            return DispatchResult(ok=False, detail="refusing to send ntfy token over non-HTTPS")
        headers = {"Title": title.encode("ascii", "replace").decode(), "Priority": priority}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if tags:
            headers["Tags"] = ",".join(tags)
        try:
            r = await self._http.post(f"{url}/{topic}", headers=headers,
                                      content=message.encode("utf-8"))
            r.raise_for_status()
            return DispatchResult(ok=True, detail=f"ntfy:{topic}")
        except Exception as e:
            return DispatchResult(ok=False, detail=f"{type(e).__name__}: {str(e)[:160]}")

    def _safe_body(self, ctx: FireContext) -> str:
        sev = ctx.event.get("severity_text") or "?"
        if ctx.safe_summary:
            return f"[{sev}] {ctx.safe_summary}"
        return f"Severity {sev} — matched on {ctx.event.get('source')}. See Ringdown for detail."

    async def open(self, ctx: FireContext, target: dict) -> DispatchResult:
        title = f"Ringdown: {ctx.rule.get('name')} on {ctx.event.get('source')}"
        return await self._push(target, title, self._safe_body(ctx),
                                priority="high", tags=["rotating_light"])

    async def feed(self, ctx: FireContext, target: dict, handle: str) -> DispatchResult:
        title = f"Ringdown (still active): {ctx.rule.get('name')} on {ctx.event.get('source')}"
        return await self._push(target, title, self._safe_body(ctx),
                                priority="default", tags=["repeat"])

    async def push_system(self, target: dict, title: str, message: str, *,
                          priority: str = "high", tags=None) -> DispatchResult:
        """Operational notice NOT tied to a rule firing (e.g. the judge signalling the
        LLM backend is unreachable). Same public-safe channel — pass no sensitive detail."""
        return await self._push(target, title, message, priority=priority, tags=tags)
