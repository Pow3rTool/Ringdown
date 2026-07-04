"""ringdown.webui — admin-only live view (log tail + alerts + semantic-eval trace) over Entra SSO.

A separate process from the collector and the MCP; it only READS the shared
Postgres. Auth is the OIDC authorization-code flow (PKCE) with **private_key_jwt
client authentication** — a certificate, not a shared secret — and access is gated
on the ``Ringdown.Admin`` app role carried in the ID token. No Graph calls.

  browser -> /auth/login -> Entra -> /auth/callback (code+PKCE, cert assertion)
          -> validate id_token (JWKS/aud/iss/nonce) -> require admin role
          -> signed session cookie -> /  (SSE live tail of events + alert firings)

Run:  python -m ringdown.webui   (bind 127.0.0.1:$RINGDOWN_WEBUI_PORT; nginx fronts TLS)
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import secrets
import time
import uuid
from html import escape
from urllib.parse import urlencode

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jwt import PyJWKClient
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.responses import (HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse,
                                  StreamingResponse)
from starlette.routing import Route

from . import config, db

# `offline_access` asks Entra for a refresh token so the operator can be kept
# signed in without the full interactive flow. In the v2.0 endpoint this is an
# OIDC scope requested at runtime (like openid/profile/email, which this app
# already requests without listing them in the app-reg's requiredResourceAccess),
# so no app-registration change is required to obtain the refresh token.
_SCOPE = "openid profile email offline_access"
_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_jwks = PyJWKClient(f"{config.AUTHORITY}/discovery/v2.0/keys")


# --- OIDC helpers ------------------------------------------------------------
def _client_assertion() -> str:
    """A short-lived JWT signed by our private key, proving we are the client
    (private_key_jwt). x5t = base64url(sha1(cert DER)) tells Entra which uploaded
    cert to verify against."""
    with open(config.OIDC_KEY_PATH, "rb") as f:
        key = f.read()
    with open(config.OIDC_CERT_PATH, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    x5t = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA1())).decode().rstrip("=")
    now = int(time.time())
    token_ep = f"{config.AUTHORITY}/oauth2/v2.0/token"
    return jwt.encode(
        {"aud": token_ep, "iss": config.CLIENT_ID, "sub": config.CLIENT_ID,
         "jti": str(uuid.uuid4()), "nbf": now, "iat": now, "exp": now + 300},
        key, algorithm="RS256", headers={"x5t": x5t})


def _validate_id_token(id_token: str, nonce: str | None = None) -> dict:
    """Verify signature (JWKS), audience, issuer, and — for the interactive login
    only — the nonce. A refreshed id_token carries no nonce (there was no fresh
    authorize request), so `nonce=None` skips that check. Sync (PyJWKClient uses
    urllib) — call via run_in_threadpool."""
    signing_key = _jwks.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token, signing_key.key, algorithms=["RS256"],
        audience=config.CLIENT_ID, issuer=f"{config.AUTHORITY}/v2.0")
    if nonce is not None and not hmac.compare_digest(str(claims.get("nonce") or ""), nonce):
        raise ValueError("nonce mismatch")
    return claims


async def _exchange_code(http: httpx.AsyncClient, code: str, verifier: str) -> dict:
    r = await http.post(
        f"{config.AUTHORITY}/oauth2/v2.0/token",
        data={"grant_type": "authorization_code", "code": code,
              "redirect_uri": config.OIDC_REDIRECT_URI, "scope": _SCOPE,
              "code_verifier": verifier, "client_id": config.CLIENT_ID,
              "client_assertion_type": _ASSERTION_TYPE, "client_assertion": _client_assertion()})
    r.raise_for_status()
    return r.json()


async def _refresh_grant(http: httpx.AsyncClient, refresh_token: str) -> dict:
    """Redeem a refresh token for a fresh id/access token (and a rotated refresh
    token — Entra rotates on every use). Same cert client-auth as the code
    exchange. Raises on any non-2xx (expired/revoked token) so the caller can
    fail closed and force an interactive login."""
    r = await http.post(
        f"{config.AUTHORITY}/oauth2/v2.0/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh_token,
              "scope": _SCOPE, "client_id": config.CLIENT_ID,
              "client_assertion_type": _ASSERTION_TYPE, "client_assertion": _client_assertion()})
    r.raise_for_status()
    return r.json()


# --- signed cookies (flow + opaque session id) ------------------------------
# The login-flow cookie is still a self-contained signed JWT (short-lived, no
# secret to protect). The SESSION cookie now carries ONLY an opaque `sid`; the
# session itself — including the refresh token — lives server-side in Postgres.
def _sign(payload: dict) -> str:
    return jwt.encode(payload, config.SESSION_SECRET, algorithm="HS256")


def _unsign(token: str) -> dict | None:
    try:
        return jwt.decode(token, config.SESSION_SECRET, algorithms=["HS256"])
    except Exception:
        return None


def _set_cookie(resp, name: str, value: str, max_age: int) -> None:
    resp.set_cookie(name, value, max_age=max_age, httponly=True, secure=True,
                    samesite="lax", path="/")


def _sid_from_cookie(request) -> str | None:
    """The opaque session id carried in the signed `rd_session` cookie (None if
    absent, tampered, or past the cookie's own JWT expiry)."""
    c = request.cookies.get("rd_session")
    d = _unsign(c) if c else None
    return d.get("sid") if d else None


# --- refresh-token encryption at rest (AES-256-GCM) --------------------------
def _enc_key() -> bytes:
    return hashlib.sha256(config.SESSION_ENC_KEY.encode()).digest()  # 32 bytes


def _encrypt_rt(rt: str) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    return AESGCM(_enc_key()).encrypt(nonce, rt.encode(), None), nonce


def _decrypt_rt(ct: bytes, nonce: bytes) -> str:
    return AESGCM(_enc_key()).decrypt(bytes(nonce), bytes(ct), None).decode()


async def _audit(pool, oid, upn, action: str, ok: bool, detail: dict) -> None:
    """Best-effort auth audit; never let logging break the request."""
    with contextlib.suppress(Exception):
        await db.execute(pool,
            "INSERT INTO audit (actor_oid, actor_upn, action, detail, ok) "
            "VALUES (%s,%s,%s,%s::jsonb,%s)",
            (oid, upn, action, json.dumps(detail), ok))


# --- server-side session store ----------------------------------------------
async def _new_session(pool, claims: dict, tok: dict) -> str:
    """Create a session row from a validated login. Requires a refresh token —
    its absence means Entra did not honor `offline_access` (consent not granted),
    which we surface loudly rather than silently degrading to a short session."""
    rt = tok.get("refresh_token")
    if not rt:
        raise ValueError("no refresh_token in token response — offline_access not granted")
    sid = secrets.token_urlsafe(32)
    ct, nonce = _encrypt_rt(rt)
    await db.execute(pool,
        "INSERT INTO webui_sessions "
        "(sid, oid, upn, name, refresh_enc, refresh_nonce, access_exp, absolute_exp) "
        "VALUES (%s,%s,%s,%s,%s,%s, now() + make_interval(secs => %s),"
        "        now() + make_interval(days => %s))",
        (sid, claims.get("oid"), claims.get("preferred_username"), claims.get("name"),
         ct, nonce, int(tok.get("expires_in", 3600)), config.SESSION_ABSOLUTE_CAP_DAYS))
    await _audit(pool, claims.get("oid"), claims.get("preferred_username"), "webui_login", True, {})
    return sid


async def _load_session(request):
    """Return the live session row (identity) for this request, or None. A row is
    live only while not revoked and before its absolute ceiling — everything else
    resolves to None and forces an interactive login (fail-closed)."""
    sid = _sid_from_cookie(request)
    if not sid:
        return None
    return await db.fetchone(request.app.state.pool,
        "SELECT sid, oid, upn, name FROM webui_sessions "
        "WHERE sid = %s AND NOT revoked AND absolute_exp > now()", (sid,))


async def _revoke_sid(pool, sid: str) -> None:
    await db.execute(pool, "UPDATE webui_sessions SET revoked = true WHERE sid = %s", (sid,))


async def _do_refresh(request, row) -> bool:
    """Silently redeem the stored refresh token: re-validate identity, RE-CHECK
    the admin role (soft revocation — a de-roled operator is cut at next refresh),
    rotate the stored token, and push access_exp forward. Any failure revokes the
    session and returns False so the caller forces a fresh interactive login."""
    pool = request.app.state.pool
    try:
        rt = _decrypt_rt(row["refresh_enc"], row["refresh_nonce"])
        tok = await _refresh_grant(request.app.state.http, rt)
        claims = await run_in_threadpool(_validate_id_token, tok["id_token"])
        roles = {str(r).lower() for r in (claims.get("roles") or [])}
        if config.WEBUI_ADMIN_ROLE.lower() not in roles:
            raise PermissionError("admin role no longer present")
        ct, nonce = _encrypt_rt(tok.get("refresh_token") or rt)  # Entra rotates; fall back to old
        await db.execute(pool,
            "UPDATE webui_sessions SET refresh_enc=%s, refresh_nonce=%s, "
            "access_exp = now() + make_interval(secs => %s), last_seen = now() "
            "WHERE sid = %s",
            (ct, nonce, int(tok.get("expires_in", 3600)), row["sid"]))
        await _audit(pool, row.get("oid"), row.get("upn"), "webui_refresh", True, {})
        return True
    except Exception as e:
        await _revoke_sid(pool, row["sid"])
        await _audit(pool, row.get("oid"), row.get("upn"), "webui_refresh_failed", False,
                     {"err": type(e).__name__})
        return False


# --- auth routes -------------------------------------------------------------
async def login(request):
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    flow = _sign({"state": state, "nonce": nonce, "verifier": verifier,
                  "exp": int(time.time()) + 600})
    url = f"{config.AUTHORITY}/oauth2/v2.0/authorize?" + urlencode({
        "client_id": config.CLIENT_ID, "response_type": "code",
        "redirect_uri": config.OIDC_REDIRECT_URI, "scope": _SCOPE,
        "state": state, "nonce": nonce, "response_mode": "query",
        "code_challenge": challenge, "code_challenge_method": "S256"})
    resp = RedirectResponse(url, status_code=302)
    _set_cookie(resp, "rd_flow", flow, 600)
    return resp


async def callback(request):
    qp = request.query_params
    if qp.get("error"):
        return HTMLResponse(_msg("Sign-in error", f"{qp.get('error')}: {qp.get('error_description','')}"), 400)
    code, state, flow_c = qp.get("code"), qp.get("state"), request.cookies.get("rd_flow")
    if not (code and state and flow_c):
        return HTMLResponse(_msg("Bad callback", "missing code/state/flow — retry sign-in."), 400)
    flow = _unsign(flow_c)
    if not flow or not hmac.compare_digest(flow.get("state", ""), state):
        return HTMLResponse(_msg("Sign-in expired", "the login flow expired or state mismatched — retry."), 400)
    try:
        tok = await _exchange_code(request.app.state.http, code, flow["verifier"])
        claims = await run_in_threadpool(_validate_id_token, tok["id_token"], flow["nonce"])
    except Exception as e:
        return HTMLResponse(_msg("Token validation failed", type(e).__name__), 400)
    roles = {str(r).lower() for r in (claims.get("roles") or [])}
    if config.WEBUI_ADMIN_ROLE.lower() not in roles:
        who = claims.get("preferred_username") or claims.get("name") or "you"
        return HTMLResponse(_msg("Access denied (403)",
            f"{who} is signed in but lacks the {config.WEBUI_ADMIN_ROLE} role."), 403)
    try:
        sid = await _new_session(request.app.state.pool, claims, tok)
    except Exception as e:
        return HTMLResponse(_msg("Sign-in incomplete",
            f"could not establish a session ({type(e).__name__}). If this persists, "
            "offline_access may not be granted for the app."), 400)
    cap = config.SESSION_ABSOLUTE_CAP_DAYS * 86400
    cookie = _sign({"sid": sid, "exp": int(time.time()) + cap})
    resp = RedirectResponse("/", status_code=302)
    _set_cookie(resp, "rd_session", cookie, cap)
    resp.delete_cookie("rd_flow", path="/")
    return resp


async def logout(request):
    sid = _sid_from_cookie(request)
    if sid:
        await _revoke_sid(request.app.state.pool, sid)
        await _audit(request.app.state.pool, None, None, "webui_logout", True, {})
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("rd_session", path="/")
    return resp


# --- data (read-only) + SSE --------------------------------------------------
def _iso(ts) -> str:
    return ts.strftime("%H:%M:%S") if hasattr(ts, "strftime") else "?"


def _ms(ts):
    # Epoch milliseconds (UTC) — the sortable, timezone-independent instant the
    # browser needs both to interleave the three streams chronologically and to
    # render the time in the viewer's local zone. `ts` is a tz-aware timestamptz,
    # so .timestamp() is the correct POSIX instant regardless of DB session zone.
    return int(ts.timestamp() * 1000) if hasattr(ts, "timestamp") else None


def _logitem(r: dict) -> dict:
    return {"t": "log", "ts": _iso(r["ts"]), "ts_ms": _ms(r["ts"]), "source": r["source"],
            "sev": r.get("severity_text"), "sevnum": r.get("severity") or 0,
            "prog": r.get("program"), "body": r.get("body")}


def _alertitem(r: dict) -> dict:
    return {"t": "alert", "ts": _iso(r["fired_at"]), "ts_ms": _ms(r["fired_at"]), "rule": r.get("rule"),
            "source": r.get("source"), "disp": r.get("disposition") or "fire"}


def _evalitem(r: dict) -> dict:
    # Compact line for the stream; the heavy detail (summary_sent, llm_raw) is
    # fetched on click via /api/eval/{id} so it isn't pushed to every client.
    return {"t": "eval", "id": r["id"], "ts": _iso(r["evaluated_at"]),
            "ts_ms": _ms(r["evaluated_at"]), "rule": r.get("rule"),
            "source": r.get("source"), "fired": bool(r.get("fired")), "sev": r.get("severity"),
            "why": r.get("why"), "n": r.get("event_count") or 0, "trig": r.get("trigger_kind"),
            "ok": bool(r.get("llm_ok")), "ms": r.get("latency_ms")}


def _ev_filters(qp) -> tuple[list, list]:
    """Server-side event filters from the stream's query params, so the log
    backfill returns the latest-N *matching* rows (not the latest-N, then filtered
    in the browser — which hid older matches outside the last 200). Same clauses
    are applied to the live tail so it streams only matching lines. All params are
    bound (ILIKE substrings); the browser reconnects the stream when these change."""
    clauses, params = [], []
    try:
        sev = int(qp.get("sev") or 0)
    except ValueError:
        sev = 0
    if sev > 0:
        clauses.append("severity >= %s"); params.append(sev)
    src = (qp.get("src") or "").strip()
    if src:
        clauses.append("source ILIKE %s"); params.append(f"%{src}%")
    q = (qp.get("q") or "").strip()
    if q:
        clauses.append("(source ILIKE %s OR program ILIKE %s OR body ILIKE %s)")
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    return clauses, params


# Which event kinds the client wants streamed. Absent param = all three (the
# default view). Present-but-empty (e.g. "kinds=") = stream nothing. This is the
# prod-scale lever: the kind checkboxes drive it so the SERVER stops shipping a
# kind the operator has hidden — the browser never has to parse+drop the log
# firehose just to show only evals during an incident.
def _kinds(qp) -> set[str]:
    if "kinds" not in qp:
        return {"log", "alert", "eval"}
    return {k.strip() for k in (qp.get("kinds") or "").split(",")
            if k.strip() in ("log", "alert", "eval")}


def _q_cond(qp, cols: tuple[str, ...]) -> tuple[str, list]:
    """Bound ILIKE-any-of clause for the text search box, applied to the alert /
    eval backfill+tail so an older match isn't hidden outside the latest-N window
    (the same guarantee _ev_filters gives logs). Column names are hardcoded, not
    user input; the search value is always a bound param. sev/src stay log-only."""
    q = (qp.get("q") or "").strip()
    if not q:
        return "", []
    return "(" + " OR ".join(f"{c} ILIKE %s" for c in cols) + ")", [f"%{q}%"] * len(cols)


async def stream(request):
    if await _load_session(request) is None:
        return PlainTextResponse("unauthenticated", 401)
    sid = _sid_from_cookie(request)
    pool = request.app.state.pool
    qp = request.query_params
    kinds = _kinds(qp)
    clauses, fp = _ev_filters(qp)
    ev_where = (" AND " + " AND ".join(clauses)) if clauses else ""
    back_where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    al_cond, al_p = _q_cond(qp, ("r.name", "ae.source", "ae.disposition"))
    se_cond, se_p = _q_cond(qp, ("r.name", "se.source", "se.why"))
    try:
        lim = min(max(int(qp.get("limit") or 300), 1), 2000)
    except ValueError:
        lim = 300

    # A hidden kind is never queried and never streamed — the server, not the
    # browser, drops it. Each enabled kind backfills `lim` matching rows so
    # narrowing to one kind (e.g. evals-only) yields a deep, filtered history
    # rather than the old fixed-50 window. All filters applied in SQL.
    AL_COLS = "ae.id, ae.fired_at, ae.source, ae.disposition, r.name AS rule"
    AL_FROM = "FROM alert_events ae LEFT JOIN alert_rules r ON r.id = ae.rule_id"
    SE_COLS = ("se.id, se.evaluated_at, se.source, se.fired, se.severity, se.why, "
               "se.event_count, se.trigger_kind, se.llm_ok, se.latency_ms, r.name AS rule")
    SE_FROM = "FROM semantic_evals se LEFT JOIN alert_rules r ON r.id = se.rule_id"

    async def gen():
        last_ev = last_al = last_se = 0
        # --- backfill the enabled kinds (latest-N matching rows, emitted oldest-first) ---
        if "log" in kinds:
            back = await db.fetch(pool, "SELECT id, ts, source, severity, severity_text, program, body "
                                        "FROM events" + back_where + " ORDER BY id DESC LIMIT %s",
                                  fp + [lim])
            last_ev = back[0]["id"] if back else 0
            for r in reversed(back):
                yield f"data: {json.dumps(_logitem(r))}\n\n"
        if "alert" in kinds:
            ab = await db.fetch(pool, f"SELECT {AL_COLS} {AL_FROM}"
                                      + ((" WHERE " + al_cond) if al_cond else "")
                                      + " ORDER BY ae.id DESC LIMIT %s", al_p + [lim])
            last_al = ab[0]["id"] if ab else 0
            for r in reversed(ab):
                yield f"data: {json.dumps(_alertitem(r))}\n\n"
        if "eval" in kinds:
            eb = await db.fetch(pool, f"SELECT {SE_COLS} {SE_FROM}"
                                      + ((" WHERE " + se_cond) if se_cond else "")
                                      + " ORDER BY se.id DESC LIMIT %s", se_p + [lim])
            last_se = eb[0]["id"] if eb else 0
            for r in reversed(eb):
                yield f"data: {json.dumps(_evalitem(r))}\n\n"
        yield "retry: 3000\n\n"   # EventSource reconnect delay after a drop (ms)
        # --- live tail: poll only the enabled kinds by id cursor ---
        idle = 0            # loop ticks since the last byte sent (heartbeat trigger)
        recheck = 0         # loop ticks since the last session validity re-check
        while True:
            if await request.is_disconnected():
                break
            # Soft revocation: if the session was revoked mid-stream (logout, a
            # failed refresh, or a lost admin role during a keepalive), tear the
            # long-lived stream down so the client is bounced to login.
            recheck += 1
            if recheck * 1.0 >= 30:
                recheck = 0
                if await _load_session(request) is None:
                    break
            pe, pa, ps = last_ev, last_al, last_se   # cursor snapshot (did we send anything?)
            if "log" in kinds:
                evs = await db.fetch(pool, "SELECT id, ts, source, severity, severity_text, program, body "
                                           "FROM events WHERE id > %s" + ev_where
                                           + " ORDER BY id LIMIT 500", [last_ev] + fp)
                for r in evs:
                    last_ev = r["id"]
                    yield f"data: {json.dumps(_logitem(r))}\n\n"
            if "alert" in kinds:
                als = await db.fetch(pool, f"SELECT {AL_COLS} {AL_FROM} WHERE ae.id > %s"
                                           + ((" AND " + al_cond) if al_cond else "")
                                           + " ORDER BY ae.id", [last_al] + al_p)
                for r in als:
                    last_al = r["id"]
                    yield f"data: {json.dumps(_alertitem(r))}\n\n"
            if "eval" in kinds:
                ses = await db.fetch(pool, f"SELECT {SE_COLS} {SE_FROM} WHERE se.id > %s"
                                           + ((" AND " + se_cond) if se_cond else "")
                                           + " ORDER BY se.id", [last_se] + se_p)
                for r in ses:
                    last_se = r["id"]
                    yield f"data: {json.dumps(_evalitem(r))}\n\n"
            # Heartbeat: if the tick sent no rows, count idle time and emit an SSE
            # comment before an intermediary's idle timeout can drop a quiet stream.
            if (last_ev, last_al, last_se) != (pe, pa, ps):
                idle = 0
            else:
                idle += 1
                if idle * 1.0 >= config.SSE_HEARTBEAT_SECONDS:
                    idle = 0
                    yield ": keepalive\n\n"
            await asyncio.sleep(1.0)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                                      "Connection": "keep-alive"})


async def eval_detail(request):
    """Full trace for one semantic evaluation — the click-in view: the rule
    CONDITION, the window meta, EXACTLY what the LLM was shown (summary_sent) and
    the raw reply it returned (llm_raw), plus the parsed verdict. Read-only."""
    if await _load_session(request) is None:
        return PlainTextResponse("unauthenticated", 401)
    try:
        eid = int(request.path_params["id"])
    except (ValueError, KeyError):
        return PlainTextResponse("bad id", 400)
    r = await db.fetchone(request.app.state.pool,
        "SELECT se.*, r.name AS rule, r.pattern AS condition "
        "FROM semantic_evals se LEFT JOIN alert_rules r ON r.id = se.rule_id "
        "WHERE se.id = %s", (eid,))
    if not r:
        return PlainTextResponse("not found", 404)
    ea = r.get("evaluated_at")
    return JSONResponse({
        "id": r["id"], "rule": r.get("rule"), "rule_id": r.get("rule_id"),
        "condition": r.get("condition"),
        "evaluated_at": ea.strftime("%Y-%m-%d %H:%M:%SZ") if hasattr(ea, "strftime") else None,
        "source": r.get("source"), "trigger": r.get("trigger_kind"),
        "window_from_id": r.get("window_from_id"), "window_to_id": r.get("window_to_id"),
        "event_count": r.get("event_count"), "elapsed_s": r.get("elapsed_s"),
        "fired": bool(r.get("fired")), "severity": r.get("severity"), "why": r.get("why"),
        "llm_ok": bool(r.get("llm_ok")), "latency_ms": r.get("latency_ms"),
        "model": r.get("model"), "summary_sent": r.get("summary_sent"),
        "reasoning": r.get("reasoning"), "llm_raw": r.get("llm_raw"),
    })


async def index(request):
    sess = await _load_session(request)
    if sess is None:
        return RedirectResponse("/auth/login", status_code=302)
    who = escape(sess.get("name") or sess.get("upn") or "admin", quote=True)
    page = _PAGE.replace("__WHO__", who).replace("__PING_MS__", str(config.KEEPALIVE_PING_SECONDS * 1000))
    return HTMLResponse(page)


async def keepalive(request):
    """Browser heartbeat: slides the session and, when the access token is within
    the refresh skew, silently re-validates with Entra (which also re-checks the
    admin role and rotates the refresh token). Returns 401 the moment the session
    is gone/revoked/expired so the page can bounce to the interactive login."""
    pool = request.app.state.pool
    sid = _sid_from_cookie(request)
    if not sid:
        return JSONResponse({"ok": False}, 401)
    row = await db.fetchone(pool,
        "SELECT sid, oid, upn, refresh_enc, refresh_nonce, "
        "       (access_exp <= now() + make_interval(secs => %s)) AS needs_refresh "
        "FROM webui_sessions WHERE sid = %s AND NOT revoked AND absolute_exp > now()",
        (config.REFRESH_SKEW_SECONDS, sid))
    if not row:
        return JSONResponse({"ok": False}, 401)
    if row["needs_refresh"] and not await _do_refresh(request, row):
        return JSONResponse({"ok": False}, 401)
    await db.execute(pool, "UPDATE webui_sessions SET last_seen = now() WHERE sid = %s", (sid,))
    return JSONResponse({"ok": True})


async def healthz(request):
    return PlainTextResponse("ok")


def _msg(title: str, detail: str) -> str:
    t = title.replace("<", "&lt;"); d = detail.replace("<", "&lt;")
    return (f"<!doctype html><meta charset=utf-8><title>Ringdown</title>"
            f"<body style='font:15px system-ui;background:#0b0e14;color:#c9d1d9;padding:3rem'>"
            f"<h2 style='color:#e6edf3'>{t}</h2><p style='color:#8b949e'>{d}</p>"
            f"<p><a style='color:#58a6ff' href='/auth/login'>&larr; try sign-in again</a></p>")


@contextlib.asynccontextmanager
async def _lifespan(app):
    app.state.pool = db.make_pool(config.DB_DSN)
    await app.state.pool.open()
    app.state.http = httpx.AsyncClient(timeout=httpx.Timeout(15.0))
    try:
        yield
    finally:
        await app.state.http.aclose()
        await app.state.pool.close()


def build_app() -> Starlette:
    return Starlette(lifespan=_lifespan, routes=[
        Route("/", index),
        Route("/auth/login", login),
        Route("/auth/callback", callback),
        Route("/auth/logout", logout),
        Route("/api/stream", stream),
        Route("/api/keepalive", keepalive, methods=["POST"]),
        Route("/api/eval/{id}", eval_detail),
        Route("/healthz", healthz),
    ])


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Ringdown · live</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{ --bg:#0b0e14; --fg:#c9d1d9; --dim:#6e7681; --panel:#0e131b; --line:#1c2230; --in:#10151f; }
  *{box-sizing:border-box}
  html,body{margin:0;min-height:100%;background:var(--bg);color:var(--fg);
    font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  header{position:sticky;top:0;z-index:3;display:flex;gap:14px;align-items:center;padding:7px 14px;
    background:var(--panel);border-bottom:1px solid var(--line);font-weight:600}
  header .t{color:#e6edf3;letter-spacing:.5px}
  header .s{color:var(--dim);font-weight:400}
  header .grow{flex:1}
  header a{color:#58a6ff;text-decoration:none}
  header .dot{width:9px;height:9px;border-radius:50%;background:#3fb950;display:inline-block;margin-right:5px}
  header .dot.off{background:#f85149}
  #bar{position:sticky;top:37px;z-index:2;display:flex;flex-wrap:wrap;gap:8px;align-items:center;
    padding:7px 14px;background:#0c1119;border-bottom:1px solid var(--line)}
  #bar input,#bar select{background:var(--in);color:var(--fg);border:1px solid var(--line);
    border-radius:5px;padding:4px 7px;font:inherit}
  #bar input[type=text]{min-width:140px}
  #bar label{color:var(--dim);user-select:none;cursor:pointer}
  #bar .btn{background:var(--in);border:1px solid var(--line);border-radius:5px;padding:4px 10px;
    color:var(--fg);cursor:pointer}
  #bar .btn:hover{border-color:#388bfd}
  #wrap{padding:6px 0 44px}
  .row{padding:1px 14px;white-space:pre-wrap;word-break:break-word;border-left:3px solid transparent}
  .row .ts{color:var(--dim)} .row .src{color:#79c0ff} .row .prog{color:#a5d6ff}
  .sev-err,.sev-crit,.sev-alert,.sev-emerg{color:#ff7b72}
  .sev-warning,.sev-warn{color:#d29922}
  .sev-notice{color:#58a6ff} .sev-info,.sev-debug{color:#8b949e}
  .alert{background:#23161a;border-left:3px solid #f85149;color:#ffa198;font-weight:600;padding:3px 14px}
  .ts{color:var(--dim);font-variant-numeric:tabular-nums;white-space:pre}
  .badge{display:inline-block;border-radius:3px;padding:0 6px;margin:0 6px;font-size:11px;background:#30363d;color:#c9d1d9}
  .badge.opened{background:#3fb950;color:#0b0e14}
  /* semantic-eval rows: click to inspect what the LLM saw/decided */
  .eval{padding:3px 14px;border-left:3px solid #8957e5;cursor:pointer}
  .eval:hover{background:#161226}
  .eval .rule{color:#d2a8ff} .eval .meta{color:var(--dim)}
  .eval.fired{border-left-color:#d29922;background:#1e1a12}
  .eval.err{border-left-color:#6e7681;opacity:.85}
  .badge.fired{background:#d29922;color:#0b0e14}
  .badge.quiet{background:#30363d;color:#8b949e}
  .badge.err{background:#6e7681;color:#0b0e14}
  /* click-in detail modal */
  #modal{position:fixed;inset:0;z-index:9;display:none;background:rgba(1,4,9,.72)}
  #modal.on{display:block}
  #modal .box{position:absolute;top:4vh;left:50%;transform:translateX(-50%);width:min(920px,94vw);
    max-height:92vh;overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px}
  #modal .hd{position:sticky;top:0;display:flex;gap:10px;align-items:center;padding:10px 16px;
    background:var(--panel);border-bottom:1px solid var(--line)}
  #modal .hd .x{margin-left:auto;cursor:pointer;color:var(--dim);font-size:18px;padding:0 4px}
  #modal .bd{padding:12px 16px}
  #modal h3{margin:14px 0 5px;color:#d2a8ff;font-size:11px;letter-spacing:.6px;text-transform:uppercase}
  #modal h3:first-child{margin-top:0}
  #modal pre{background:var(--in);border:1px solid var(--line);border-radius:6px;padding:9px 11px;
    white-space:pre-wrap;word-break:break-word;color:#c9d1d9;margin:0}
  #modal .kv{color:var(--dim)} #modal .kv b{color:#c9d1d9;font-weight:600}
  #modal .cond{color:#e6edf3}
</style></head>
<body>
<header><span class="t">RINGDOWN · live</span>
  <span class="s"><span id="dot" class="dot"></span><span id="status">connecting…</span></span>
  <span class="s">logs <b id="nlog">0</b></span>
  <span class="s">alerts <b id="nalert" style="color:#ff7b72">0</b></span>
  <span class="s">evals <b id="neval" style="color:#d2a8ff">0</b></span>
  <span class="grow"></span>
  <span class="s">__WHO__</span>
  <a href="/auth/logout">sign out</a>
</header>
<div id="bar">
  <label>min sev
    <select id="fSev">
      <option value="0">all</option><option value="9">info+</option><option value="10">notice+</option>
      <option value="13">warning+</option><option value="17">error+</option><option value="18">crit+</option>
    </select></label>
  <input type="text" id="fSrc" placeholder="source filter (substr)">
  <input type="text" id="fQ" placeholder="search text">
  <label><input type="checkbox" id="cLog" checked> logs</label>
  <label><input type="checkbox" id="cAlert" checked> alerts</label>
  <label><input type="checkbox" id="cEval" checked> evals</label>
  <span class="btn" id="clear">clear buffer</span>
</div>
<div id="wrap"></div>
<div id="modal"><div class="box">
  <div class="hd"><b id="mTitle">semantic evaluation</b><span class="x" id="mClose">✕</span></div>
  <div class="bd" id="mBody"></div>
</div></div>
<script>
(function(){
  var wrap=document.getElementById('wrap'), items=[], MAXI=2500, MAXD=1500, nlog=0,nalert=0,neval=0, seq=0;
  // Real datetime in the VIEWER's timezone (server sends UTC epoch-ms in d.ts_ms).
  var TF=new Intl.DateTimeFormat(undefined,{year:'2-digit',month:'2-digit',day:'2-digit',
    hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
  function fmtTs(d){ return d.ts_ms==null ? (d.ts||'?') : TF.format(new Date(d.ts_ms)); }
  var elSev=document.getElementById('fSev'), elSrc=document.getElementById('fSrc'), elQ=document.getElementById('fQ'),
      cLog=document.getElementById('cLog'), cAlert=document.getElementById('cAlert'), cEval=document.getElementById('cEval');
  document.getElementById('clear').onclick=function(){items=[];wrap.innerHTML='';nlog=nalert=neval=0;counts();};
  // source / min-sev / search are filtered SERVER-SIDE (so the backfill returns the latest
  // matching rows, not the latest-N then client-filtered) -> reconnect the stream on change,
  // debounced. The kind checkboxes are cheap client-side toggles -> just rebuild, no reconnect.
  [elSev,elSrc,elQ].forEach(function(e){e.addEventListener('input',scheduleReconnect);e.addEventListener('change',scheduleReconnect);});
  // Kind selection is now SERVER-side (a hidden kind isn't streamed at all — the
  // browser must never buffer the log firehose just to drop it at prod scale).
  // rebuild() hides it instantly for snappy feedback; the debounced reconnect then
  // re-subscribes to only the enabled kinds.
  [cLog,cAlert,cEval].forEach(function(e){e.addEventListener('change',function(){rebuild();scheduleReconnect();});});
  function counts(){document.getElementById('nlog').textContent=nlog;document.getElementById('nalert').textContent=nalert;
    document.getElementById('neval').textContent=neval;}
  function passes(d){
    if(d.t==='log'   && !cLog.checked)   return false;
    if(d.t==='alert' && !cAlert.checked) return false;
    if(d.t==='eval'  && !cEval.checked)  return false;
    // min-sev + source-substring are LOG filters — don't hide alert/eval meta-rows
    // (those are governed by their own checkbox + the search box below).
    if(d.t==='log'){
      var m=parseInt(elSev.value||'0',10); if((d.sevnum||0) < m) return false;
      var src=(elSrc.value||'').toLowerCase(); if(src && (''+(d.source||'')).toLowerCase().indexOf(src)<0) return false;
    }
    var q=(elQ.value||'').toLowerCase();
    if(q){ var hay=[d.source,d.prog,d.body,d.rule,d.disp,d.why].join(' ').toLowerCase(); if(hay.indexOf(q)<0) return false; }
    return true;
  }
  function el(cls,txt){var s=document.createElement('span');if(cls)s.className=cls;s.textContent=txt;return s;}
  function node(d){
    if(d.t==='alert'){
      var a=document.createElement('div');a.className='alert';
      a.appendChild(el('ts',fmtTs(d)+' '));
      a.appendChild(document.createTextNode('● ALERT '));
      a.appendChild(el('',(d.rule||'?')+' '));
      a.appendChild(el('badge '+(d.disp==='opened'?'opened':''),d.disp||'fire'));
      a.appendChild(el('',' on '+(d.source||'?')));
      return a;
    }
    if(d.t==='eval'){
      var e=document.createElement('div');
      e.className='eval'+(d.fired?' fired':'')+(d.ok?'':' err');
      e.title='click to see what the LLM saw & decided';
      e.appendChild(el('ts',fmtTs(d)+' '));
      e.appendChild(document.createTextNode('◆ EVAL '));
      e.appendChild(el('rule',(d.rule||'?')+' '));
      e.appendChild(el('badge '+(!d.ok?'err':(d.fired?'fired':'quiet')), !d.ok?'llm-error':(d.fired?'FIRED':'no-fire')));
      var meta=(d.n||0)+' lines · '+(d.trig||'?')+(d.ms!=null?' · '+d.ms+'ms':'')+(d.source?' · '+d.source:'');
      e.appendChild(el('meta',' '+meta));
      if(d.fired&&d.why) e.appendChild(el('meta',' — '+d.why));
      e.onclick=function(){ showEval(d.id); };
      return e;
    }
    var r=document.createElement('div');r.className='row';
    var sev=(d.sev||'').toLowerCase(); if(sev)r.classList.add('sev-'+sev);
    r.appendChild(el('ts',fmtTs(d)+' '));
    r.appendChild(el('src',(d.source||'?')+' '));
    if(d.sev)r.appendChild(el('','['+d.sev+'] '));
    if(d.prog)r.appendChild(el('prog',d.prog+': '));
    r.appendChild(el('',d.body||''));
    return r;
  }
  // `items` is kept sorted NEWEST-FIRST by (ts_ms, arrival seq) so the three
  // streams (logs / alerts / evals) interleave by real event time regardless of
  // the order the server flushes them in — that grouping was the ordering bug.
  // Each rendered item caches its DOM node (n.__d back-ref) so we can splice a
  // late-arriving row into the right on-screen position without a full rebuild.
  function keyOf(d){ return d.ts_ms==null ? Infinity : d.ts_ms; }  // unknown time -> top
  function findIdx(d){                        // first index whose item is older than d
    var lo=0, hi=items.length;
    while(lo<hi){ var mid=(lo+hi)>>1, it=items[mid];
      if(d.k>it.k || (d.k===it.k && d.seq>it.seq)) hi=mid; else lo=mid+1; }
    return lo;
  }
  function trim(){                            // cap DOM nodes; drop from the oldest end
    while(wrap.childNodes.length>MAXD){ var last=wrap.lastChild; if(last.__d) last.__d.node=null; wrap.removeChild(last); }
  }
  function rebuild(){
    wrap.innerHTML=''; var c=0;
    for(var i=0;i<items.length;i++) items[i].node=null;
    for(var i=0;i<items.length && c<MAXD;i++){ var d=items[i];
      if(passes(d)){ var n=node(d); n.__d=d; d.node=n; wrap.appendChild(n); c++; } }
  }
  function ingest(d){
    d.k=keyOf(d); d.seq=seq++;
    var i=findIdx(d); items.splice(i,0,d);
    if(d.t==='alert') nalert++; else if(d.t==='eval') neval++; else nlog++;
    counts();
    if(passes(d)){
      var n=node(d); n.__d=d; d.node=n;
      var ref=null;                           // insert before the next currently-rendered item
      for(var j=i+1;j<items.length;j++){ if(items[j].node){ ref=items[j].node; break; } }
      wrap.insertBefore(n, ref); trim();
    }
    // evict the oldest once over the buffer cap (after rendering, so a row that
    // sorts dead-last in a full buffer is dropped cleanly rather than orphaned)
    if(items.length>MAXI){ var rm=items.pop(); if(rm.node&&rm.node.parentNode){ rm.node.parentNode.removeChild(rm.node); rm.node=null; } }
  }
  // --- click-in detail: fetch the full trace for one evaluation --------------
  var modal=document.getElementById('modal'), mBody=document.getElementById('mBody'),
      mTitle=document.getElementById('mTitle');
  function closeModal(){ modal.className=''; }
  document.getElementById('mClose').onclick=closeModal;
  modal.onclick=function(ev){ if(ev.target===modal) closeModal(); };
  document.addEventListener('keydown',function(ev){ if(ev.key==='Escape') closeModal(); });
  function esc(s){ var d=document.createElement('div'); d.textContent=(s==null?'':''+s); return d.innerHTML; }
  function row(k,v){ return '<div class="kv">'+esc(k)+': <b>'+esc(v)+'</b></div>'; }
  function showEval(id){
    mTitle.textContent='semantic evaluation #'+id;
    mBody.innerHTML='<div class="kv">loading…</div>';
    modal.className='on';
    fetch('/api/eval/'+id).then(function(r){ if(!r.ok) throw new Error(r.status); return r.json(); })
      .then(function(d){
        var win=(d.window_from_id!=null?('('+d.window_from_id+', '+d.window_to_id+']'):'—');
        var verdict=(!d.llm_ok?'LLM error / unparseable':(d.fired?('FIRED ['+(d.severity||'?')+']'):'no-fire'));
        var h='';
        h+='<h3>decision</h3><div class="kv"><b>'+esc(verdict)+'</b>'+(d.why?' — '+esc(d.why):'')+'</div>';
        h+='<h3>rule condition</h3><div class="cond">'+esc(d.condition||'(none)')+'</div>';
        h+='<h3>evaluation</h3>';
        h+=row('rule', (d.rule||'?')+(d.rule_id?(' (#'+d.rule_id+')'):''));
        h+=row('evaluated at', d.evaluated_at);
        h+=row('triggered by', d.trigger+(d.elapsed_s!=null?(' · '+Math.round(d.elapsed_s)+'s since prior eval'):''));
        h+=row('window (event ids)', win+' · '+(d.event_count||0)+' lines · top source '+(d.source||'?'));
        h+=row('model', (d.model||'?')+(d.latency_ms!=null?(' · '+d.latency_ms+'ms'):''));
        h+='<h3>what the LLM saw (window digest)</h3><pre>'+esc(d.summary_sent||'(empty)')+'</pre>';
        if(d.reasoning) h+='<h3>model reasoning (reasoning_content)</h3><pre>'+esc(d.reasoning)+'</pre>';
        h+='<h3>model reply ('+(d.reasoning?'content':'raw')+')</h3><pre>'+esc(d.llm_raw||'(empty)')+'</pre>';
        mBody.innerHTML=h;
      })
      .catch(function(e){ mBody.innerHTML='<div class="kv">failed to load: '+esc(e.message||e)+'</div>'; });
  }
  var es=null, reTimer=null;
  function streamURL(){
    var p=new URLSearchParams();
    if((elSev.value||'0')!=='0') p.set('sev',elSev.value);
    if(elSrc.value) p.set('src',elSrc.value);
    if(elQ.value)   p.set('q',elQ.value);
    // omit `kinds` when all three are on (server default = all); otherwise send the
    // enabled subset so the server streams only those (0 selected => streams nothing).
    var ks=[]; if(cLog.checked)ks.push('log'); if(cAlert.checked)ks.push('alert'); if(cEval.checked)ks.push('eval');
    if(ks.length<3) p.set('kinds',ks.join(','));
    var s=p.toString(); return '/api/stream'+(s?('?'+s):'');
  }
  function connect(){
    if(es) es.close();
    // fresh filtered backfill -> reset the buffer so stale non-matching lines don't linger
    items=[];wrap.innerHTML='';nlog=nalert=neval=0;counts();
    es=new EventSource(streamURL());
    es.onopen=function(){document.getElementById('status').textContent='connected';document.getElementById('dot').className='dot';};
    es.onerror=function(){document.getElementById('status').textContent='reconnecting…';document.getElementById('dot').className='dot off';};
    es.onmessage=function(e){ try{ ingest(JSON.parse(e.data)); }catch(_){} };
  }
  function scheduleReconnect(){ clearTimeout(reTimer); reTimer=setTimeout(connect,350); }
  // Keepalive: slides the server-side session and drives silent OIDC refresh. A
  // 401 means the session is truly gone (past the absolute cap, revoked, or a
  // failed refresh) -> go through the full interactive login.
  function keepalive(){
    fetch('/api/keepalive',{method:'POST',credentials:'same-origin',cache:'no-store'})
      .then(function(r){ if(r.status===401){ location.href='/auth/login'; } })
      .catch(function(){});
  }
  setInterval(keepalive, __PING_MS__);
  connect();
})();
</script>
</body></html>
"""


def main() -> None:
    config.validate_webui()
    import uvicorn
    uvicorn.run(build_app(), host="127.0.0.1", port=config.WEBUI_PORT, log_level="info")


if __name__ == "__main__":
    main()
