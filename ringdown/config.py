"""ringdown.config — environment configuration + fail-closed validation.

One module both processes import. `.env` (KEY=VALUE, 0600) is loaded once at
import; real environment always wins. Each entrypoint calls the validator for
its role (`validate_collector()` / `validate_mcp()`) which raises SystemExit on
any missing/placeholder secret — Ringdown is high-blast-radius (it summons
agents that act), so it refuses to start half-configured rather than run in a
surprising partial state.
"""
from __future__ import annotations

import os
import re

_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def load_env(path: str | None = None) -> None:
    """Load KEY=VALUE lines from `.env` without a dependency; env wins."""
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                # Strip a trailing ` # comment` (whitespace-hash, so a literal '#'
                # inside a value survives) and any surrounding quotes — otherwise
                # an inline comment in the file becomes part of the value.
                v = re.sub(r"\s+#.*$", "", v).strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                    v = v[1:-1]
                os.environ.setdefault(k.strip(), v)
    except FileNotFoundError:
        pass


load_env()


def _s(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _i(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _placeholder(v: str) -> bool:
    """True if a value is empty or an obvious un-filled placeholder."""
    v = str(v).strip()
    return (not v) or ("<" in v) or (">" in v) or ("REPLACE" in v.upper())


# --- storage -----------------------------------------------------------------
DB_DSN = _s("RINGDOWN_DB_DSN")
EMBED_DIM = _i("RINGDOWN_EMBED_DIM", 768)

# --- retention (monitoring window, NOT a log archive) ------------------------
# Drop event partitions + hide sources older than this. 0 disables auto-retention.
RETENTION_DAYS = _i("RINGDOWN_RETENTION_DAYS", 90)
RETENTION_INTERVAL = _f("RINGDOWN_RETENTION_INTERVAL", 86400)  # tick period (s), daily

# --- collector / ingest ------------------------------------------------------
SYSLOG_UDP = _s("RINGDOWN_SYSLOG_UDP", "0.0.0.0:514")
SYSLOG_TCP = _s("RINGDOWN_SYSLOG_TCP", "0.0.0.0:514")
BATCH_MAX = _i("RINGDOWN_BATCH_MAX", 500)
BATCH_MS = _i("RINGDOWN_BATCH_MS", 1000)
QUEUE_MAX = _i("RINGDOWN_QUEUE_MAX", 50_000)

# --- router / loop-guard -------------------------------------
INCIDENT_REUSE_TTL = _f("RINGDOWN_INCIDENT_REUSE_TTL", 7200)   # reuse an open handle within this
FEED_INTERVAL = _f("RINGDOWN_FEED_INTERVAL", 60)               # min gap between feeds to a handle
GLOBAL_RATE_CEILING = _i("RINGDOWN_GLOBAL_RATE_CEILING", 120)  # max dispatches/min across all rules

# --- turnstone dispatcher (owner-OBO) ----------------------------------------
TURNSTONE_URL = _s("RINGDOWN_TURNSTONE_URL", "http://127.0.0.1:8090").rstrip("/")
TURNSTONE_ADMIN_TOKEN = _s("RINGDOWN_TURNSTONE_ADMIN_TOKEN")   # mints per-user (owner) tokens
TURNSTONE_DEFAULT_OWNER = _s("RINGDOWN_TURNSTONE_DEFAULT_OWNER")  # fallback owner user_id
# Deployment-wide default turnstone project: new chats are filed under this when
# neither the rule nor its target names one. server.require_project refuses
# projectless creates, so with this set no alert can dispatch projectless; leave
# it (and per-rule/target project) empty and turnstone dispatch degrades to ntfy.
# The run-as owner must be a member of the project or turnstone drops it.
TURNSTONE_DEFAULT_PROJECT = _s("RINGDOWN_TURNSTONE_DEFAULT_PROJECT")
TOKEN_TTL_HOURS = _f("RINGDOWN_TURNSTONE_TOKEN_TTL_HOURS", 20)    # cache minted tokens this long
# Scopes on the minted per-owner run-as token. Default excludes "approve" on
# purpose (least-privilege): the design routes destructive remediation through the
# human-approval gate, so the automated identity should not self-approve. Widen
# only if a run-as flow provably needs it.
OBO_SCOPES = _s("RINGDOWN_OBO_SCOPES", "read,write")

# --- ntfy dispatcher + fallback (public topic — safe by construction) --------
NTFY_URL = _s("RINGDOWN_NTFY_URL").rstrip("/")
NTFY_TOKEN = _s("RINGDOWN_NTFY_TOKEN")
NTFY_TOPIC = _s("RINGDOWN_NTFY_TOPIC", "ringdown")
# When a stateful dispatch throws, we degrade to this ntfy target so a human is
# never blind. Empty disables the fallback (dispatch errors then only audit).
FALLBACK_NTFY_TOPIC = _s("RINGDOWN_FALLBACK_NTFY_TOPIC") or NTFY_TOPIC
# SSRF guard: extra hostnames a per-target ntfy config may point at, beyond the
# configured NTFY_URL host. Empty = only the NTFY_URL host is allowed. This stops
# a Ringdown.Write principal from aiming a target's `url` at an internal service.
NTFY_ALLOWED_HOSTS = [h.strip().lower() for h in _s("RINGDOWN_NTFY_ALLOWED_HOSTS").split(",") if h.strip()]

# --- L2 semantic judge (optional; empty = regex-only) ------------------------
LLM_URL = _s("RINGDOWN_LLM_URL").rstrip("/")
LLM_MODEL = _s("RINGDOWN_LLM_MODEL", "agent")
LLM_API_KEY = _s("RINGDOWN_LLM_API_KEY")
# Reasoning models spend tokens thinking before the verdict, and in this vLLM the
# thinking counts against max_tokens (no separate reasoning budget). DeepSeek is
# pinned at max thinking (~4-6k tokens) — budget generously so the verdict JSON
# always lands AFTER the <think> pass instead of truncating to a null content.
LLM_MAX_TOKENS = _i("RINGDOWN_LLM_MAX_TOKENS", 8000)
# Sampler temperature is OMITTED by default: vLLM then uses the loaded model's own
# generation_config.json recipe (the creator's values). We do NOT hardcode temp=0 —
# it's in the known loop-causing range and fights the reasoning pass. The lab rotates
# models day to day, so set this ONLY to pin a value for a specific loaded model
# (per its HF card); empty = let the model's own recipe apply. Reasoning effort is
# forced high server-side (vLLM --default-chat-template-kwargs.reasoning_effort=high).
def _fopt(name: str):
    v = os.environ.get(name, "").strip()
    try:
        return float(v) if v else None
    except ValueError:
        return None
LLM_TEMPERATURE = _fopt("RINGDOWN_LLM_TEMPERATURE")
SEMANTIC_TICK = _f("RINGDOWN_SEMANTIC_TICK", 30)
SEMANTIC_SPIKE = _i("RINGDOWN_SEMANTIC_SPIKE", 100)  # per-rule NEW-line burst -> judge early
# Token guards for the judge tier:
#  * MIN_INTERVAL — hard floor: never invoke the judge for a given rule more often
#    than this, even on a spike (clamps a sub-floor window_seconds up to it too).
#    Sub-interval spikes are the main token-burn path; this is the primary cap.
#  * MAX_PER_MIN — global loop-guard: max judge LLM calls/min across ALL semantic
#    rules. Excess rules defer to the next tick (still floor-gated). 0 disables.
SEMANTIC_MIN_INTERVAL = _f("RINGDOWN_SEMANTIC_MIN_INTERVAL", 300)
SEMANTIC_MAX_PER_MIN = _i("RINGDOWN_SEMANTIC_MAX_PER_MIN", 20)
# LLM-outage heartbeat: if the judge backend is unreachable continuously for this
# long, push ONE ntfy notice (never repeated until it recovers, then one recovery
# notice). Long by design — planned rig shutdowns (storms) shouldn't page instantly.
# 0 disables. Note: a collector restart resets the downtime clock.
SEMANTIC_OUTAGE_ALERT_S = _f("RINGDOWN_SEMANTIC_OUTAGE_ALERT_S", 86400)  # 24h

# --- MCP control-plane front door (Entra bearer) -----------------------------
MCP_PUBLIC_HOST = _s("RINGDOWN_PUBLIC_HOST", "localhost")
MCP_PORT = _i("RINGDOWN_PORT", 8787)
TENANT_ID = _s("RINGDOWN_TENANT_ID")
CLIENT_ID = _s("RINGDOWN_CLIENT_ID")
AUDIENCE = [x for x in (CLIENT_ID, f"api://{CLIENT_ID}", *_s("RINGDOWN_AUDIENCE").split(",")) if x.strip()]
REQUIRED_SCOPE = _s("RINGDOWN_REQUIRED_SCOPE")
ALLOWED_CLIENTS = [x.strip() for x in _s("RINGDOWN_ALLOWED_CLIENTS").split(",") if x.strip()]
# oids/upns with operator break-glass (disable a runaway, reassign orphaned rules)
OPERATORS = [x.strip().lower() for x in _s("RINGDOWN_OPERATORS").split(",") if x.strip()]
AUDIT_LOG = _s("RINGDOWN_AUDIT_LOG", "/opt/ringdown/var/audit.log")
MAX_OUTPUT_CHARS = _i("RINGDOWN_MAX_OUTPUT_CHARS", 60000)
DEFAULT_LIMIT = _i("RINGDOWN_DEFAULT_LIMIT", 200)
MAX_LIMIT = _i("RINGDOWN_MAX_LIMIT", 2000)
AUTH_DEBUG = _s("RINGDOWN_AUTH_DEBUG").lower() in ("1", "true", "yes")

READ_ROLES = {"ringdown.read", "ringdown.write"}
WRITE_ROLES = {"ringdown.write"}

# --- admin WebUI (interactive Entra SSO, certificate client-auth) ------------
# A browser-facing, admin-only live view (log tail + alert list). Unlike the MCP
# (machine bearer), this uses the OIDC authorization-code flow with private_key_jwt
# client authentication (a certificate, NOT a shared secret) and gates on the
# Ringdown.Admin app role in the ID token. No Graph calls.
WEBUI_PORT = _i("RINGDOWN_WEBUI_PORT", 8088)
OIDC_REDIRECT_URI = _s("RINGDOWN_OIDC_REDIRECT_URI")  # https://<host>/auth/callback
OIDC_KEY_PATH = _s("RINGDOWN_OIDC_KEY_PATH", "/opt/ringdown/oidc/oidc.key")   # private key (0600)
OIDC_CERT_PATH = _s("RINGDOWN_OIDC_CERT_PATH", "/opt/ringdown/oidc/oidc.crt")  # public cert (for x5t)
SESSION_SECRET = _s("RINGDOWN_SESSION_SECRET")        # HS256 key for the session/flow cookies
SESSION_TTL_HOURS = _f("RINGDOWN_SESSION_TTL_HOURS", 8)   # access-token-tier lifetime (now the refresh cadence)
WEBUI_ADMIN_ROLE = _s("RINGDOWN_WEBUI_ADMIN_ROLE", "Ringdown.Admin")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

# --- WebUI server-side sessions + silent OIDC refresh ------------------------
# The session cookie carries only an opaque sid; the refresh token lives in the
# webui_sessions table, ENCRYPTED with a key derived (SHA-256) from this secret.
# Distinct from SESSION_SECRET so cookie-signing and token-encryption keys can be
# rotated independently. Fail-closed: the WebUI refuses to start without it.
SESSION_ENC_KEY = _s("RINGDOWN_SESSION_ENC_KEY")
# Hard ceiling on how long a session may live regardless of activity or refresh.
SESSION_ABSOLUTE_CAP_DAYS = _i("RINGDOWN_SESSION_ABSOLUTE_CAP_DAYS", 30)
# Refresh the access token (and re-validate the operator + role with Entra) once
# it is within this many seconds of expiry — driven by the browser keepalive ping.
REFRESH_SKEW_SECONDS = _i("RINGDOWN_REFRESH_SKEW_SECONDS", 300)
# How often (seconds) the browser pings /api/keepalive to slide the session and
# trigger silent refresh. Well under the shortest proxy/idle timeout in the path.
KEEPALIVE_PING_SECONDS = _i("RINGDOWN_KEEPALIVE_PING_SECONDS", 240)
# SSE heartbeat: a `: keepalive` comment every N seconds so an idle live-log
# stream never sends zero bytes (which a stock nginx proxy_read_timeout of 60s
# would silently drop). Must be comfortably under that 60s.
SSE_HEARTBEAT_SECONDS = _i("RINGDOWN_SSE_HEARTBEAT_SECONDS", 20)


def validate_webui() -> None:
    """Fail-closed gate for the WebUI process. No unauthenticated path exists."""
    if not DB_DSN:
        raise SystemExit("RINGDOWN_DB_DSN is required.")
    if not (_GUID.match(TENANT_ID) and _GUID.match(CLIENT_ID)):
        raise SystemExit("RINGDOWN_TENANT_ID and RINGDOWN_CLIENT_ID must be real tenant/app GUIDs.")
    if _placeholder(OIDC_REDIRECT_URI):
        raise SystemExit("RINGDOWN_OIDC_REDIRECT_URI is required (the app-reg web redirect URI).")
    if len(SESSION_SECRET) < 32:
        raise SystemExit("RINGDOWN_SESSION_SECRET must be set (>=32 chars) — cookies are signed with it.")
    if len(SESSION_ENC_KEY) < 32:
        raise SystemExit("RINGDOWN_SESSION_ENC_KEY must be set (>=32 chars) — refresh tokens are encrypted with it.")
    if SESSION_ABSOLUTE_CAP_DAYS < 1:
        raise SystemExit("RINGDOWN_SESSION_ABSOLUTE_CAP_DAYS must be >= 1.")
    for p in (OIDC_KEY_PATH, OIDC_CERT_PATH):
        if not os.path.isfile(p):
            raise SystemExit(f"OIDC cert/key not found at {p!r} — generate it and upload the cert to Entra.")


def validate_collector() -> None:
    """Fail-closed gate for the collector (ingest + dispatch) process."""
    if not DB_DSN:
        raise SystemExit("RINGDOWN_DB_DSN is required (run scripts/provision-db.sh or set it in .env).")
    # A dispatch path must be reachable, else a fired hook is silently lost.
    turnstone_on = bool(TURNSTONE_ADMIN_TOKEN)
    ntfy_on = bool(NTFY_URL and NTFY_TOKEN)
    if not (turnstone_on or ntfy_on):
        raise SystemExit(
            "no dispatch path configured — set the ntfy dispatcher "
            "(RINGDOWN_NTFY_URL + RINGDOWN_NTFY_TOKEN) and/or the turnstone owner-OBO path "
            "(RINGDOWN_TURNSTONE_ADMIN_TOKEN). Refusing to run blind.")


def validate_mcp() -> None:
    """Fail-closed gate for the MCP control-plane process. Every request is
    cryptographically validated, so the tenant/app/scope/client pins must all
    be real — there is NO unauthenticated path."""
    if not DB_DSN:
        raise SystemExit("RINGDOWN_DB_DSN is required.")
    if _placeholder(TENANT_ID) or _placeholder(CLIENT_ID):
        raise SystemExit("RINGDOWN_TENANT_ID and RINGDOWN_CLIENT_ID must be real values.")
    if not (_GUID.match(TENANT_ID) and _GUID.match(CLIENT_ID)):
        raise SystemExit("RINGDOWN_TENANT_ID and RINGDOWN_CLIENT_ID must be specific tenant/app GUIDs.")
    if _placeholder(REQUIRED_SCOPE):
        raise SystemExit("RINGDOWN_REQUIRED_SCOPE is required — pin the coarse 'valid caller' scope.")
    if not ALLOWED_CLIENTS or any(_placeholder(c) for c in ALLOWED_CLIENTS):
        raise SystemExit("RINGDOWN_ALLOWED_CLIENTS is required — pin the calling client (turnstone).")
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG) or ".", exist_ok=True)
        with open(AUDIT_LOG, "a"):
            pass
    except Exception as e:
        raise SystemExit(f"audit log {AUDIT_LOG!r} is not writable ({type(e).__name__}) — refusing to start.")
