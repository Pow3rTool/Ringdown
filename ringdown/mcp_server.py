"""ringdown.mcp_server — the Entra-gated control plane (query + CRUD).

The INBOUND half: agents/operators query the log store and curate alert rules +
targets. Same front-door shape as the Ringdown prototype / partyline / cloudflare-dns-mcp: every
request carries an Entra bearer, cryptographically validated
(JWKS sig/aud/iss/exp/scope/client) before anything runs. There is NO unauth path.

Roles: Ringdown.Read = query. Ringdown.Write = curate rules/targets (Write also
satisfies reads). Operator break-glass (config RINGDOWN_OPERATORS or the
Ringdown.Operator role) can act on any owner's rows.

Ownership: rules/targets are visible-to-all (read) but writable only
by the owning (human oid, bot appid) pair, ∪ operator. A different bot acting as
the SAME human still cannot CRUD another bot's rows.

Live propagation: DB triggers fire NOTIFY 'rules_changed' on every rule/target/
binding write, so the collector refreshes its ruleset — this module does not
NOTIFY explicitly (the trigger catches every writer, including manual psql).

Talks to Postgres only (no direct IPC with the collector). Run: python -m ringdown.mcp_server
"""
from __future__ import annotations

import json
import re
import sys
import time
import calendar
from collections import namedtuple
from contextlib import asynccontextmanager

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from . import config

config.validate_mcp()

# dispatcher types the target registry can actually service today (fail-closed:
# reject registration of a type we can't dispatch — SSRF-prone generic webhook
# templates are M4 and gated behind a host allow-list, not enabled here).
KNOWN_TARGET_TYPES = {"ntfy", "turnstone"}
IDENTITY_POLICIES = {"run-as-owner", "static-svc", "none"}
# break-glass, cross-owner. The documented app role is Ringdown.Operator (see README
# app-reg + RINGDOWN_OPERATORS); "ringdown.admin" is kept as a back-compat alias.
ADMIN_ROLES = {"ringdown.operator", "ringdown.admin"}


def _validate_target_config(ttype: str, cfg: dict) -> str | None:
    """Reject unsafe target config at write time. Returns an error string or None.

    - ntfy: a per-target ``url`` may only point at the configured ntfy host or an
      explicitly allow-listed one (SSRF guard — mirrors NtfyDispatcher.url_allowed).
    - turnstone: blanket ``auto_approve`` is forbidden; only a scoped
      ``auto_approve_tools`` list may relax the human-approval gate.
    """
    if ttype == "ntfy":
        url = (cfg.get("url") or "").strip()
        if url:
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or "").lower()
            allowed = {(urlparse(config.NTFY_URL).hostname or "").lower()} | set(config.NTFY_ALLOWED_HOSTS)
            allowed.discard("")
            if host not in allowed:
                return (f"ntfy url host {host!r} is not allow-listed (SSRF guard). Use the "
                        f"configured ntfy server, or add the host to RINGDOWN_NTFY_ALLOWED_HOSTS.")
    if ttype == "turnstone":
        if cfg.get("auto_approve") is True:
            return ("blanket auto_approve is not permitted — it would disable the human-approval "
                    "gate for destructive tools. Use auto_approve_tools with a scoped list instead.")
    return None


# ReDoS guard (sec review B5): an L1 pattern runs against EVERY ingested line on
# the single-threaded collector loop, and Python `re` has no match timeout — a
# catastrophic-backtracking pattern from a Write principal can wedge ingest
# fleet-wide. We reject the two things that cause it: over-long patterns and a
# quantifier applied to a group that itself contains an unbounded quantifier
# (``(a+)+``, ``(.*)*``, ``(\d+|x)*`` …), plus absurd bounded repetition.
_MAX_PATTERN_LEN = 512
_NESTED_QUANT = re.compile(r"\([^()]*[+*][^()]*\)\s*[*+]|\([^()]*[+*][^()]*\)\s*\{\d*,?\d*\}")
_BIG_REPEAT = re.compile(r"\{\s*(\d+)\s*(?:,\s*(\d+)\s*)?\}")

def _regex_safe(pattern: str) -> str | None:
    """Returns an error string if the regex is a ReDoS risk on the hot path, else None."""
    if len(pattern) > _MAX_PATTERN_LEN:
        return f"pattern too long ({len(pattern)} > {_MAX_PATTERN_LEN} chars) — simplify it."
    if _NESTED_QUANT.search(pattern):
        return ("pattern has a nested unbounded quantifier (e.g. (a+)+ / (.*)* ) which can cause "
                "catastrophic backtracking and wedge the collector. Rewrite without nesting "
                "quantifiers over a group that already repeats.")
    for m in _BIG_REPEAT.finditer(pattern):
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if hi > 1000:
            return f"repetition {{{m.group(1)},{m.group(2) or ''}}} is too large (> 1000)."
    return None

_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
Ident = namedtuple("Ident", "oid upn appid roles")
_pool: AsyncConnectionPool | None = None


# --- auth / authz / audit ----------------------------------------------------
def _bearer(ctx) -> str:
    try:
        h = ctx.request_context.request.headers.get("authorization", "") or ""
        return h[7:].strip() if h[:7].lower() == "bearer " else ""
    except Exception:
        return ""


_jwks = None


def _jwks_client():
    global _jwks
    if _jwks is None:
        from jwt import PyJWKClient
        _jwks = PyJWKClient(f"https://login.microsoftonline.com/{config.TENANT_ID}/discovery/v2.0/keys")
    return _jwks


def _identity(bearer: str) -> Ident | None:
    """(oid, upn, appid, roles) ONLY after the bearer is cryptographically
    verified for this tenant+app. None on any failure — callers MUST reject."""
    if not bearer:
        return None
    try:
        import jwt
        key = _jwks_client().get_signing_key_from_jwt(bearer).key
        claims = jwt.decode(bearer, key, algorithms=["RS256"], audience=config.AUDIENCE,
                            options={"require": ["exp"], "verify_aud": True})
        reason = None
        if claims.get("iss", "") not in (f"https://login.microsoftonline.com/{config.TENANT_ID}/v2.0",
                                          f"https://sts.windows.net/{config.TENANT_ID}/"):
            reason = "iss"
        elif claims.get("tid") != config.TENANT_ID:
            reason = "tid"
        elif config.REQUIRED_SCOPE and config.REQUIRED_SCOPE not in str(claims.get("scp", "")).split():
            reason = "scp"
        elif config.ALLOWED_CLIENTS and (claims.get("azp") or claims.get("appid")) not in config.ALLOWED_CLIENTS:
            reason = "azp/appid"
        if reason:
            if config.AUTH_DEBUG:
                print(f"AUTH-DEBUG reject[{reason}]", file=sys.stderr, flush=True)
            return None
        oid = claims.get("oid") or claims.get("sub") or "?"
        upn = claims.get("preferred_username") or claims.get("upn") or oid
        appid = claims.get("azp") or claims.get("appid") or ""
        roles = [str(r).lower() for r in (claims.get("roles") or [])]
        if config.AUTH_DEBUG:
            print(f"AUTH-DEBUG ok upn={upn} azp={appid} aud={claims.get('aud')} "
                  f"scp={claims.get('scp')} roles={claims.get('roles')} ver={claims.get('ver')}",
                  file=sys.stderr, flush=True)
        return Ident(oid, upn, appid, roles)
    except Exception as e:
        if config.AUTH_DEBUG:
            print(f"AUTH-DEBUG reject[{type(e).__name__}: {e}]", file=sys.stderr, flush=True)
        return None


def _auth(ctx) -> Ident | None:
    return _identity(_bearer(ctx))


def _authz(ident: Ident, write: bool) -> tuple[bool, str | None]:
    have = set(ident.roles or [])
    need = config.WRITE_ROLES if write else config.READ_ROLES
    # Ringdown.Admin is a superset: it satisfies read+write (and additionally
    # bypasses per-row ownership below), so an admin needs only the one role.
    if not (have & need) and not _is_admin(ident):
        verb = "curate rules/targets (the Ringdown.Write role)" if write else "query (the Ringdown.Read role)"
        return False, (f"not authorized: this operation requires {verb}. Ask an admin to assign it "
                       "on the Ringdown app in Entra.")
    return True, None


def _is_admin(ident: Ident) -> bool:
    """Break-glass: the Ringdown.Operator app role (or Ringdown.Admin alias), or an
    oid/UPN in RINGDOWN_OPERATORS."""
    if set(ident.roles or []) & ADMIN_ROLES:
        return True
    ops = set(config.OPERATORS)
    return ident.oid.lower() in ops or (ident.upn or "").lower() in ops


def _owns(ident: Ident, owner_oid, owner_bot) -> bool:
    """(human, bot) ownership: BOTH the oid and the bot appid must match."""
    return (owner_oid or "") == ident.oid and (owner_bot or "") == (ident.appid or "")


def _deny_not_owner(kind: str, owner_oid) -> str:
    return (f"not yours ({kind} owner: {owner_oid or 'unknown'}). A different agent/user can't modify "
            "it — ask the owner or a Ringdown.Admin (break-glass).")


async def _audit(ident: Ident | None, action: str, detail: dict, ok: bool, *, critical: bool = True):
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "oid": ident.oid if ident else "?", "who": ident.upn if ident else "?",
           "bot": ident.appid if ident else "", "action": action, "detail": detail, "ok": bool(ok)}
    try:  # durable file log (chmod 600 dir)
        import os
        os.makedirs(os.path.dirname(config.AUDIT_LOG) or ".", exist_ok=True)
        with open(config.AUDIT_LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception as e:
        if critical:
            print(f"AUDIT-WRITE-FAILED {type(e).__name__}: {rec}", file=sys.stderr, flush=True)
    try:  # queryable DB audit
        await _exec("INSERT INTO audit (actor_oid, actor_upn, action, detail, ok) VALUES (%s,%s,%s,%s,%s)",
                    (rec["oid"], rec["who"], action, Jsonb(detail), bool(ok)))
    except Exception:
        pass


def _err(msg: str) -> str:
    return json.dumps({"error": msg})


def _out(obj) -> str:
    s = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    if len(s) <= config.MAX_OUTPUT_CHARS:
        return s
    return s[:config.MAX_OUTPUT_CHARS] + f"\n…[TRUNCATED — narrow your query]"


# --- helpers: time parse, glob->LIKE (ported from the Ringdown prototype) --------------------
def _parse_iso(s: str):
    s = (s or "").strip().rstrip("Zz")
    if not s:
        return None
    frac = 0.0
    if "." in s:
        s, fr = s.split(".", 1)
        digits = re.sub(r"\D", "", fr)
        if digits:
            frac = float("0." + digits)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return calendar.timegm(time.strptime(s, fmt)) + frac
        except ValueError:
            continue
    return None


def _window(since_iso, since_seconds, until_iso):
    since = _parse_iso(since_iso) if since_iso else None
    if since is None and since_seconds and since_seconds > 0:
        since = time.time() - float(since_seconds)
    until = _parse_iso(until_iso) if until_iso else None
    return since, until


def _glob_clause(col: str, glob: str):
    if any(c in glob for c in "*?"):
        esc = glob.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        esc = esc.replace("*", "%").replace("?", "_")
        return f"{col} LIKE %s", esc
    return f"{col} = %s", glob


# --- MCP ---------------------------------------------------------------------
@asynccontextmanager
async def _lifespan(_server):
    global _pool
    if config.AUTH_DEBUG:
        print("[ringdown-mcp] WARNING: RINGDOWN_AUTH_DEBUG is ON — verified token claims "
              "(upn/azp/aud/scp/roles) are logged to stderr. Do not leave this on in prod.",
              file=sys.stderr, flush=True)
    _pool = AsyncConnectionPool(config.DB_DSN, min_size=1, max_size=4, open=False,
                                kwargs={"row_factory": dict_row})
    await _pool.open()
    try:
        yield {}
    finally:
        await _pool.close()


mcp = FastMCP("ringdown",
    instructions=(
        "Query the Ringdown log store and curate alert hooks + notification targets. Logs are "
        "keyed by SOURCE (device/host) and time. Query: search_logs / timeline / list_sources. "
        "Rules: register_alert / update_alert / delete_alert / disable_alert / list_alerts / "
        "test_alert / get_alert_history. Targets (how alerts reach a responder): register_target / "
        "update_target / delete_target / list_targets, and bind_target / unbind_target to attach a "
        "target to a rule. severity is the OTel severity_number 1..24 (9=info, 13=warning, 17=error, "
        "21+=fatal). Times are UTC ISO-8601; use since_seconds for relative windows. Reads need "
        "Ringdown.Read; changes need Ringdown.Write and you may only modify your own rows (operators "
        "excepted)."),
    host="127.0.0.1", port=config.MCP_PORT, stateless_http=True, json_response=True,
    streamable_http_path="/mcp", lifespan=_lifespan,
    transport_security=TransportSecuritySettings(
        allowed_hosts=[config.MCP_PUBLIC_HOST, f"{config.MCP_PUBLIC_HOST}:443",
                       f"127.0.0.1:{config.MCP_PORT}", f"localhost:{config.MCP_PORT}"],
        allowed_origins=[f"https://{config.MCP_PUBLIC_HOST}", f"http://127.0.0.1:{config.MCP_PORT}"]))


async def _fetch(sql, params):
    async with _pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(sql, params)
        return await cur.fetchall()


async def _fetchone(sql, params):
    async with _pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(sql, params)
        return await cur.fetchone()


async def _exec(sql, params):
    async with _pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(sql, params)
        row = await cur.fetchone() if cur.description else None
    return row


# === query tools =============================================================
@mcp.tool()
async def search_logs(ctx: Context, source: str = "", contains: str = "", regex: str = "",
                      program: str = "", severity_min: int = 0, since_iso: str = "",
                      since_seconds: float = 0.0, until_iso: str = "", limit: int = 0) -> str:
    """Search log events (newest first) by any combination of: source (device, exact or glob
    'rtr*'), contains (full-text), regex (POSIX ~ on body), program, severity_min (OTel floor:
    13=warn/17=err/21=fatal), and a UTC window (since_iso/since_seconds/until_iso; 'last 6h'
    = since_seconds=21600). Read-only (Ringdown.Read)."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation (sig/aud/iss/exp/scope/client)")
    ok, why = _authz(ident, write=False)
    if not ok:
        return _err(why)
    where, params = [], []
    if source:
        c, p = _glob_clause("source", source); where.append(c); params.append(p)
    if program:
        c, p = _glob_clause("program", program); where.append(c); params.append(p)
    if contains:
        where.append("search @@ plainto_tsquery('english', %s)"); params.append(contains)
    if regex:
        try:
            re.compile(regex)
        except re.error as e:
            return _err(f"invalid regex: {e}")
        where.append("body ~ %s"); params.append(regex)
    if severity_min and severity_min > 0:
        where.append("severity >= %s"); params.append(int(severity_min))
    since, until = _window(since_iso, since_seconds, until_iso)
    if since is not None:
        where.append("ts >= to_timestamp(%s)"); params.append(since)
    if until is not None:
        where.append("ts <= to_timestamp(%s)"); params.append(until)
    lim = min(int(limit) if limit and limit > 0 else config.DEFAULT_LIMIT, config.MAX_LIMIT)
    sql = ("SELECT id, ts, source, severity, severity_text, program, body, template_id FROM events"
           + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY ts DESC LIMIT %s")
    params.append(lim)
    try:
        rows = await _fetch(sql, params)
    except Exception as e:
        return _err(f"query failed: {type(e).__name__}: {str(e)[:200]}")
    return _out({"count": len(rows), "limit": lim, "events": rows})


@mcp.tool()
async def timeline(ctx: Context, since_iso: str = "", since_seconds: float = 0.0, until_iso: str = "",
                   sources: str = "", severity_min: int = 0, limit: int = 0) -> str:
    """What happened across sources in a UTC window: events oldest→newest + a per-source count
    summary. Set the window (since_iso/until_iso or since_seconds); sources = optional CSV of
    devices (exact/glob each); severity_min = OTel floor. Read-only (Ringdown.Read)."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=False)
    if not ok:
        return _err(why)
    since, until = _window(since_iso, since_seconds, until_iso)
    if since is None and until is None:
        return _err("a time window is required: set since_iso/until_iso or since_seconds.")
    where, params = [], []
    if since is not None:
        where.append("ts >= to_timestamp(%s)"); params.append(since)
    if until is not None:
        where.append("ts <= to_timestamp(%s)"); params.append(until)
    srcs = [s.strip() for s in sources.split(",") if s.strip()]
    if srcs:
        ors = []
        for s in srcs:
            c, p = _glob_clause("source", s); ors.append(c); params.append(p)
        where.append("(" + " OR ".join(ors) + ")")
    if severity_min and severity_min > 0:
        where.append("severity >= %s"); params.append(int(severity_min))
    wsql = " WHERE " + " AND ".join(where)
    lim = min(int(limit) if limit and limit > 0 else 500, config.MAX_LIMIT)
    try:
        summary = await _fetch("SELECT source, count(*) AS events, max(severity) AS worst FROM events"
                               + wsql + " GROUP BY source ORDER BY events DESC", params)
        events = await _fetch("SELECT id, ts, source, severity, severity_text, program, body FROM events"
                              + wsql + " ORDER BY ts ASC LIMIT %s", params + [lim])
    except Exception as e:
        return _err(f"query failed: {type(e).__name__}: {str(e)[:200]}")
    return _out({"by_source": summary, "count": len(events), "events": events})


@mcp.tool()
async def list_sources(ctx: Context, glob: str = "", include_hidden: bool = False) -> str:
    """List known log sources (devices), JIT-discovered as logs arrive. Optional glob ('rtr*').
    Hidden/decommissioned devices (unseen past the retention window, or manually hidden) are
    excluded unless include_hidden=true."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=False)
    if not ok:
        return _err(why)
    clauses, params = [], []
    if glob:
        c, p = _glob_clause("source", glob); clauses.append(c); params.append(p)
    if not include_hidden:
        clauses.append("active")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = await _fetch("SELECT source, label, kind, active, first_seen, last_seen, events "
                        "FROM sources" + where + " ORDER BY active DESC, last_seen DESC", params)
    return _out({"count": len(rows), "sources": rows})


@mcp.tool()
async def set_source_active(ctx: Context, source: str, active: bool = False) -> str:
    """Hide (active=false) or un-hide (active=true) a log source. Use active=false to immediately
    decommission a device instead of waiting for the retention window; a hidden device un-hides
    itself the moment it sends another line. Write role."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=True)
    if not ok:
        return _err(why)
    row = await _exec("UPDATE sources SET active = %s WHERE source = %s "
                      "RETURNING source, active, last_seen, events", (bool(active), source))
    if not row:
        return _err(f"no known source {source!r}.")
    await _audit(ident, "set_source_active", {"source": source, "active": bool(active)}, True)
    return _out({"updated": True, **row})


# === target CRUD =============================================================
@mcp.tool()
async def register_target(ctx: Context, name: str, type: str, config_json: str = "{}",
                          identity_policy: str = "none") -> str:
    """Register a notification TARGET (how an alert reaches a responder). Needs Ringdown.Write.
      • name            — unique handle.
      • type            — 'ntfy' (public human push) or 'turnstone' (summon an agent, run-as-owner).
      • config_json     — JSON object of channel config (SENSITIVE; redacted from non-owners).
                          ntfy: {"topic": "...", "url": "...", "token": "..."} (url/token optional
                          if the collector has defaults). turnstone: {"auto_approve_tools": "notify",
                          "skill": "...", "model": "..."} — all optional; DO NOT blanket auto_approve.
      • identity_policy — 'run-as-owner' (turnstone OBO), 'static-svc', or 'none' (ntfy).
    You own the target; only you (or an operator) can change/delete it, and only you can bind it."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=True)
    if not ok:
        await _audit(ident, "register_target", {"name": name, "denied": why}, False)
        return _err(why)
    if type not in KNOWN_TARGET_TYPES:
        return _err(f"unsupported target type {type!r}; supported: {sorted(KNOWN_TARGET_TYPES)}")
    if identity_policy not in IDENTITY_POLICIES:
        return _err(f"identity_policy must be one of {sorted(IDENTITY_POLICIES)}")
    try:
        cfg = json.loads(config_json or "{}")
        if not isinstance(cfg, dict):
            raise ValueError("config must be a JSON object")
    except Exception as e:
        return _err(f"invalid config_json: {e}")
    cfg_err = _validate_target_config(type, cfg)
    if cfg_err:
        await _audit(ident, "register_target", {"name": name, "denied": cfg_err}, False)
        return _err(cfg_err)
    try:
        row = await _exec(
            "INSERT INTO targets (name, type, config, identity_policy, owner_oid, owner_upn, owner_bot) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (name, type, Jsonb(cfg), identity_policy, ident.oid, ident.upn, ident.appid))
    except Exception as e:
        return _err(f"insert failed (name unique?): {type(e).__name__}: {str(e)[:200]}")
    await _audit(ident, "register_target", {"id": row["id"], "name": name, "type": type}, True)
    return _out({"registered": True, "id": row["id"], "name": name, "type": type})


@mcp.tool()
async def list_targets(ctx: Context) -> str:
    """List targets {id, name, type, identity_policy, owner}. `config` is returned only for
    targets you own (or if you're an operator); otherwise it is redacted. Read-only."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=False)
    if not ok:
        return _err(why)
    rows = await _fetch("SELECT id, name, type, config, identity_policy, owner_oid, owner_upn, "
                        "owner_bot, created_at FROM targets ORDER BY id", [])
    op = _is_admin(ident)
    out = []
    for r in rows:
        visible = op or _owns(ident, r["owner_oid"], r["owner_bot"])
        out.append({**{k: r[k] for k in ("id", "name", "type", "identity_policy", "owner_upn", "created_at")},
                    "config": r["config"] if visible else "<redacted — not owner>"})
    return _out({"count": len(out), "targets": out})


@mcp.tool()
async def update_target(ctx: Context, target_id: int, config_json: str = "", identity_policy: str = "",
                        name: str = "") -> str:
    """Update a target's config/identity_policy/name (owner or operator only). Only non-empty
    fields change. config_json REPLACES the whole config object."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=True)
    if not ok:
        return _err(why)
    row = await _fetchone("SELECT type, owner_oid, owner_bot FROM targets WHERE id = %s", (int(target_id),))
    if not row:
        return _err(f"no target with id {target_id}.")
    if not (_owns(ident, row["owner_oid"], row["owner_bot"]) or _is_admin(ident)):
        await _audit(ident, "update_target", {"target_id": target_id, "denied": "not owner"}, False)
        return _err(_deny_not_owner("target", row["owner_oid"]))
    sets, params = [], []
    if config_json:
        try:
            cfg = json.loads(config_json)
            if not isinstance(cfg, dict):
                raise ValueError("config must be a JSON object")
        except Exception as e:
            return _err(f"invalid config_json: {e}")
        cfg_err = _validate_target_config(row["type"], cfg)
        if cfg_err:
            await _audit(ident, "update_target", {"target_id": target_id, "denied": cfg_err}, False)
            return _err(cfg_err)
        sets.append("config = %s"); params.append(Jsonb(cfg))
    if identity_policy:
        if identity_policy not in IDENTITY_POLICIES:
            return _err(f"identity_policy must be one of {sorted(IDENTITY_POLICIES)}")
        sets.append("identity_policy = %s"); params.append(identity_policy)
    if name:
        sets.append("name = %s"); params.append(name)
    if not sets:
        return _err("nothing to update (set config_json/identity_policy/name).")
    params.append(int(target_id))
    upd = await _exec(f"UPDATE targets SET {', '.join(sets)} WHERE id = %s RETURNING id, name", params)
    await _audit(ident, "update_target", {"target_id": target_id, "fields": len(sets)}, True)
    return _out({"updated": True, **upd})


@mcp.tool()
async def delete_target(ctx: Context, target_id: int) -> str:
    """Delete a target (owner or operator only). Its rule bindings are removed (cascade)."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=True)
    if not ok:
        return _err(why)
    row = await _fetchone("SELECT owner_oid, owner_bot, name FROM targets WHERE id = %s", (int(target_id),))
    if not row:
        return _err(f"no target with id {target_id}.")
    if not (_owns(ident, row["owner_oid"], row["owner_bot"]) or _is_admin(ident)):
        return _err(_deny_not_owner("target", row["owner_oid"]))
    await _exec("DELETE FROM targets WHERE id = %s", (int(target_id),))
    await _audit(ident, "delete_target", {"target_id": target_id, "name": row["name"]}, True)
    return _out({"deleted": True, "id": target_id})


# === rule CRUD ===============================================================
@mcp.tool()
async def register_alert(ctx: Context, name: str, kind: str, pattern: str, instructions: str = "",
                         source_glob: str = "", min_severity: int = 0, window_kind: str = "sliding",
                         window_seconds: int = 300, spike_lines: int = 0, cooldown_seconds: int = 300,
                         rule_order: int = 100, stop_on_match: bool = False, project_id: str = "",
                         targets: str = "") -> str:
    """Register an alert hook (needs Ringdown.Write). REQUIRED: name, kind, pattern.
      • kind='regex'    — `pattern` matched on every incoming line (L1, cheap).
      • kind='semantic' — `pattern` is a PLAIN-ENGLISH condition an LLM judges over windows (L2).
      • instructions    — per-rule triage guidance handed to the agent when it fires (strongly rec.).
      • source_glob     — restrict to devices ('rtr*'); min_severity — OTel floor (>=).
      • window_kind/window_seconds/spike_lines — L2 windowing (sliding|tumbling).
      • rule_order/stop_on_match — router order (lower first) + terminal-stop (pf `quick`).
      • project_id      — turnstone project for team visibility (carried for run-as-owner dispatch).
      • targets         — CSV of target ids to bind now (must be targets YOU own). Bind more later
                          with bind_target. A rule with NO targets never fires anywhere.
    The hook is owned by you (human+agent) and runs AS you (run-as-owner) when it fires."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=True)
    if not ok:
        await _audit(ident, "register_alert", {"name": name, "denied": why}, False)
        return _err(why)
    if kind not in ("regex", "semantic"):
        return _err("kind must be 'regex' or 'semantic'.")
    if not (name and pattern):
        return _err("name and pattern are required.")
    if window_kind not in ("sliding", "tumbling"):
        return _err("window_kind must be 'sliding' or 'tumbling'.")
    if kind == "regex":
        try:
            re.compile(pattern)
        except re.error as e:
            return _err(f"invalid regex pattern: {e}")
        unsafe = _regex_safe(pattern)
        if unsafe:
            return _err(unsafe)
    tids = []
    for t in (targets or "").split(","):
        t = t.strip()
        if not t:
            continue
        if not t.isdigit():
            return _err(f"target id {t!r} is not numeric.")
        tids.append(int(t))
    # verify caller may bind each target (owned or operator) BEFORE creating the rule
    for tid in tids:
        trow = await _fetchone("SELECT owner_oid, owner_bot FROM targets WHERE id = %s", (tid,))
        if not trow:
            return _err(f"no target with id {tid}.")
        if not (_owns(ident, trow["owner_oid"], trow["owner_bot"]) or _is_admin(ident)):
            return _err(f"cannot bind target {tid}: {_deny_not_owner('target', trow['owner_oid'])}")
    try:
        row = await _exec(
            "INSERT INTO alert_rules (name, kind, pattern, instructions, source_glob, min_severity, "
            "window_kind, window_seconds, spike_lines, cooldown_seconds, rule_order, stop_on_match, "
            "project_id, created_by, created_by_upn, created_by_bot) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (name, kind, pattern, instructions or None, source_glob or None, int(min_severity) or None,
             window_kind, int(window_seconds), int(spike_lines) or None, int(cooldown_seconds),
             int(rule_order), bool(stop_on_match), project_id or None, ident.oid, ident.upn, ident.appid))
    except Exception as e:
        return _err(f"insert failed: {type(e).__name__}: {str(e)[:200]}")
    for tid in tids:
        await _exec("INSERT INTO rule_targets (rule_id, target_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                    (row["id"], tid))
    await _audit(ident, "register_alert", {"id": row["id"], "name": name, "kind": kind, "targets": tids}, True)
    return _out({"registered": True, "id": row["id"], "name": name, "kind": kind, "bound_targets": tids})


async def _load_rule_owner(rule_id: int):
    return await _fetchone("SELECT created_by, created_by_bot, name FROM alert_rules WHERE id = %s",
                           (int(rule_id),))


@mcp.tool()
async def update_alert(ctx: Context, rule_id: int, pattern: str = "", instructions: str = "",
                       source_glob: str = "", min_severity: int = -1, window_seconds: int = -1,
                       spike_lines: int = -1, cooldown_seconds: int = -1, rule_order: int = -1,
                       stop_on_match_set: str = "", project_id: str = "") -> str:
    """Edit an existing rule in place (owner or operator only). Only fields you pass change:
    strings change when non-empty; integers change when >= 0 (use -1 to leave unchanged);
    stop_on_match_set = 'true'/'false' to change it (empty = leave). The Ringdown prototype had no in-place edit —
    this closes that gap."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=True)
    if not ok:
        return _err(why)
    owner = await _load_rule_owner(rule_id)
    if not owner:
        return _err(f"no alert rule with id {rule_id}.")
    if not (_owns(ident, owner["created_by"], owner["created_by_bot"]) or _is_admin(ident)):
        await _audit(ident, "update_alert", {"rule_id": rule_id, "denied": "not owner"}, False)
        return _err(_deny_not_owner("rule", owner["created_by"]))
    sets, params = [], []
    if pattern:
        try:
            kind = (await _fetchone("SELECT kind FROM alert_rules WHERE id = %s", (int(rule_id),)))["kind"]
            if kind == "regex":
                re.compile(pattern)
        except re.error as e:
            return _err(f"invalid regex pattern: {e}")
        if kind == "regex":
            unsafe = _regex_safe(pattern)
            if unsafe:
                return _err(unsafe)
        sets.append("pattern = %s"); params.append(pattern)
    if instructions:
        sets.append("instructions = %s"); params.append(instructions)
    if source_glob:
        sets.append("source_glob = %s"); params.append(source_glob)
    if min_severity >= 0:
        sets.append("min_severity = %s"); params.append(int(min_severity) or None)
    if window_seconds >= 0:
        sets.append("window_seconds = %s"); params.append(int(window_seconds))
    if spike_lines >= 0:
        sets.append("spike_lines = %s"); params.append(int(spike_lines) or None)
    if cooldown_seconds >= 0:
        sets.append("cooldown_seconds = %s"); params.append(int(cooldown_seconds))
    if rule_order >= 0:
        sets.append("rule_order = %s"); params.append(int(rule_order))
    if stop_on_match_set.lower() in ("true", "false"):
        sets.append("stop_on_match = %s"); params.append(stop_on_match_set.lower() == "true")
    if project_id:
        sets.append("project_id = %s"); params.append(project_id)
    if not sets:
        return _err("nothing to update.")
    params.append(int(rule_id))
    upd = await _exec(f"UPDATE alert_rules SET {', '.join(sets)} WHERE id = %s RETURNING id, name", params)
    await _audit(ident, "update_alert", {"rule_id": rule_id, "fields": len(sets)}, True)
    return _out({"updated": True, **upd})


@mcp.tool()
async def delete_alert(ctx: Context, rule_id: int) -> str:
    """Delete a rule and its bindings/incidents (owner or operator only). The Ringdown prototype had no delete."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=True)
    if not ok:
        return _err(why)
    owner = await _load_rule_owner(rule_id)
    if not owner:
        return _err(f"no alert rule with id {rule_id}.")
    if not (_owns(ident, owner["created_by"], owner["created_by_bot"]) or _is_admin(ident)):
        return _err(_deny_not_owner("rule", owner["created_by"]))
    await _exec("DELETE FROM alert_rules WHERE id = %s", (int(rule_id),))
    await _audit(ident, "delete_alert", {"rule_id": rule_id, "name": owner["name"]}, True)
    return _out({"deleted": True, "id": rule_id})


@mcp.tool()
async def disable_alert(ctx: Context, rule_id: int, enable: bool = False) -> str:
    """Disable (or re-enable with enable=true) a rule (owner or operator only). Operators use this
    as break-glass to stop a runaway or an offboarded agent's orphaned hook."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=True)
    if not ok:
        return _err(why)
    owner = await _load_rule_owner(rule_id)
    if not owner:
        return _err(f"no alert rule with id {rule_id}.")
    if not (_owns(ident, owner["created_by"], owner["created_by_bot"]) or _is_admin(ident)):
        return _err(_deny_not_owner("rule", owner["created_by"]))
    row = await _exec("UPDATE alert_rules SET enabled = %s WHERE id = %s RETURNING id, name, enabled",
                      (bool(enable), int(rule_id)))
    await _audit(ident, "disable_alert", {"rule_id": rule_id, "enabled": bool(enable)}, True)
    return _out({"updated": True, **row})


@mcp.tool()
async def list_alerts(ctx: Context, include_disabled: bool = False, mine_only: bool = False) -> str:
    """List rules (visible-to-all) with their bound target ids. include_disabled=true to see
    disabled; mine_only=true to see only rows you own. Read-only."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=False)
    if not ok:
        return _err(why)
    where, params = [], []
    if not include_disabled:
        where.append("enabled")
    if mine_only:
        where.append("created_by = %s AND created_by_bot = %s"); params += [ident.oid, ident.appid]
    wsql = (" WHERE " + " AND ".join(where)) if where else ""
    rows = await _fetch(
        "SELECT id, name, kind, pattern, source_glob, min_severity, window_kind, window_seconds, "
        "spike_lines, cooldown_seconds, rule_order, stop_on_match, enabled, project_id, last_fired, "
        "created_by_upn, created_at FROM alert_rules" + wsql + " ORDER BY rule_order, id", params)
    binds = await _fetch("SELECT rule_id, target_id FROM rule_targets", [])
    tmap: dict = {}
    for b in binds:
        tmap.setdefault(b["rule_id"], []).append(b["target_id"])
    for r in rows:
        r["target_ids"] = tmap.get(r["id"], [])
    return _out({"count": len(rows), "rules": rows})


@mcp.tool()
async def bind_target(ctx: Context, rule_id: int, target_id: int, target_order: int = 100,
                      stop_on_match: bool = False) -> str:
    """Attach a target to a rule (fan-out). You must own BOTH the rule and the target (or be an
    operator). target_order/stop_on_match are per-binding router knobs."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=True)
    if not ok:
        return _err(why)
    owner = await _load_rule_owner(rule_id)
    if not owner:
        return _err(f"no alert rule with id {rule_id}.")
    if not (_owns(ident, owner["created_by"], owner["created_by_bot"]) or _is_admin(ident)):
        return _err(_deny_not_owner("rule", owner["created_by"]))
    trow = await _fetchone("SELECT owner_oid, owner_bot FROM targets WHERE id = %s", (int(target_id),))
    if not trow:
        return _err(f"no target with id {target_id}.")
    if not (_owns(ident, trow["owner_oid"], trow["owner_bot"]) or _is_admin(ident)):
        return _err(f"cannot bind target {target_id}: {_deny_not_owner('target', trow['owner_oid'])}")
    await _exec("INSERT INTO rule_targets (rule_id, target_id, target_order, stop_on_match) "
                "VALUES (%s,%s,%s,%s) ON CONFLICT (rule_id, target_id) DO UPDATE SET "
                "target_order = EXCLUDED.target_order, stop_on_match = EXCLUDED.stop_on_match",
                (int(rule_id), int(target_id), int(target_order), bool(stop_on_match)))
    await _audit(ident, "bind_target", {"rule_id": rule_id, "target_id": target_id}, True)
    return _out({"bound": True, "rule_id": rule_id, "target_id": target_id})


@mcp.tool()
async def unbind_target(ctx: Context, rule_id: int, target_id: int) -> str:
    """Detach a target from a rule (rule owner or operator only)."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=True)
    if not ok:
        return _err(why)
    owner = await _load_rule_owner(rule_id)
    if not owner:
        return _err(f"no alert rule with id {rule_id}.")
    if not (_owns(ident, owner["created_by"], owner["created_by_bot"]) or _is_admin(ident)):
        return _err(_deny_not_owner("rule", owner["created_by"]))
    await _exec("DELETE FROM rule_targets WHERE rule_id = %s AND target_id = %s",
                (int(rule_id), int(target_id)))
    await _audit(ident, "unbind_target", {"rule_id": rule_id, "target_id": target_id}, True)
    return _out({"unbound": True, "rule_id": rule_id, "target_id": target_id})


@mcp.tool()
async def test_alert(ctx: Context, kind: str, pattern: str, source_glob: str = "",
                     min_severity: int = 0, since_seconds: float = 604800.0, limit: int = 20) -> str:
    """Dry-run a rule against HISTORY before arming it — see what it would have caught (count +
    sample). regex: lines matching `pattern`; semantic: candidate events the LLM tier would judge.
    Window defaults to 7 days. Read-only."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=False)
    if not ok:
        return _err(why)
    if kind not in ("regex", "semantic"):
        return _err("kind must be 'regex' or 'semantic'.")
    where, params = ["ts >= to_timestamp(%s)"], [time.time() - float(since_seconds)]
    if source_glob:
        c, p = _glob_clause("source", source_glob); where.append(c); params.append(p)
    if min_severity and min_severity > 0:
        where.append("severity >= %s"); params.append(int(min_severity))
    if kind == "regex":
        try:
            re.compile(pattern)
        except re.error as e:
            return _err(f"invalid regex pattern: {e}")
        unsafe = _regex_safe(pattern)
        if unsafe:
            return _err(unsafe)
        where.append("body ~ %s"); params.append(pattern)
    wsql = " WHERE " + " AND ".join(where)
    lim = min(int(limit) if limit and limit > 0 else 20, 200)
    try:
        total = (await _fetch("SELECT count(*) AS n FROM events" + wsql, params))[0]["n"]
        sample = await _fetch("SELECT id, ts, source, severity_text, program, body FROM events"
                              + wsql + " ORDER BY ts DESC LIMIT %s", params + [lim])
    except Exception as e:
        return _err(f"query failed: {type(e).__name__}: {str(e)[:200]}")
    note = ("lines this regex would have matched" if kind == "regex"
            else "candidate events the semantic/LLM tier would adjudicate (no LLM run here)")
    return _out({"kind": kind, "window_seconds": since_seconds, "would_match": total,
                 "note": note, "sample": sample})


@mcp.tool()
async def get_alert_history(ctx: Context, rule_id: int = 0, since_seconds: float = 86400.0,
                            limit: int = 100) -> str:
    """Recent alert firings {fired_at, rule, source, summary, disposition, notified}. Optionally
    scope to one rule_id. Window defaults to 24h. Read-only."""
    ident = _auth(ctx)
    if ident is None:
        return _err("unauthenticated: bearer failed validation")
    ok, why = _authz(ident, write=False)
    if not ok:
        return _err(why)
    where, params = ["ae.fired_at >= to_timestamp(%s)"], [time.time() - float(since_seconds)]
    if rule_id and rule_id > 0:
        where.append("ae.rule_id = %s"); params.append(int(rule_id))
    lim = min(int(limit) if limit and limit > 0 else 100, config.MAX_LIMIT)
    rows = await _fetch(
        "SELECT ae.id, ae.fired_at, ae.rule_id, r.name AS rule, ae.source, ae.summary, "
        "ae.disposition, ae.notified, ae.target_id FROM alert_events ae "
        "LEFT JOIN alert_rules r ON r.id = ae.rule_id WHERE " + " AND ".join(where)
        + " ORDER BY ae.fired_at DESC LIMIT %s", params + [lim])
    return _out({"count": len(rows), "firings": rows})


# Drop resource/prompt handlers we don't implement.
from mcp import types as _t
for _rt in (_t.ListResourcesRequest, _t.ReadResourceRequest, _t.ListResourceTemplatesRequest,
            _t.ListPromptsRequest, _t.GetPromptRequest, _t.SubscribeRequest, _t.UnsubscribeRequest):
    mcp._mcp_server.request_handlers.pop(_rt, None)

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
