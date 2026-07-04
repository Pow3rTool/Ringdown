"""ringdown.syslog_parse — syslog decode + template mining (pure, no I/O).

Lifted verbatim from the Ringdown prototype's collector (it parsed real Cisco IOS /
Linux / RFC5424 traffic in the lab and earned its keep). Kept as pure functions
so the ingest hot path and the test suite share exactly one decoder.

Normalizes each line to an OTel-shaped event dict; `mine_template` masks the
variable bits so we store/embed one row per message *shape*, not per line.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone

# PRI = facility*8 + severity. severity stored as OTel severity_number (1..24),
# original syslog word kept in severity_text.
_SYSLOG_SEV_NAME = {0: "emerg", 1: "alert", 2: "crit", 3: "err",
                    4: "warning", 5: "notice", 6: "info", 7: "debug"}
_SYSLOG_TO_OTEL = {0: 24, 1: 21, 2: 19, 3: 17, 4: 13, 5: 10, 6: 9, 7: 5}
_FACILITY = {0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
             6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
             16: "local0", 17: "local1", 18: "local2", 19: "local3",
             20: "local4", 21: "local5", 22: "local6", 23: "local7"}

_PRI_RE = re.compile(r"^<(\d{1,3})>")
_RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?:(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*)?"
    r"(?P<msg>.*)$")
_MON = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# Cisco IOS/IOS-XE: "[<seq>: ][<host>: ]<*?timestamp[ tz]>: %FAC-SEV-CODE: message"
_CISCO_RE = re.compile(
    r"^(?:(?P<seq>\d+): )?"
    r"(?:(?P<host>[A-Za-z0-9][A-Za-z0-9._-]*): )?"
    r"(?P<dts>[*.]?[A-Z][a-z]{2} +\d{1,2} +\d{2}:\d{2}:\d{2}(?:\.\d+)?(?: [A-Za-z]{2,5})?): "
    r"%(?P<fac>[A-Z0-9_]+)-(?P<sev>\d)-(?P<code>[A-Z0-9_]+): "
    r"(?P<msg>.*)$", re.S)


def _parse_5424_ts(s: str):
    if s == "-":
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _parse_3164_ts(s: str, now: datetime):
    """RFC3164 'Mmm dd HH:MM:SS' (no year/TZ) -> aware UTC, current year, sender-clock-UTC."""
    try:
        mon = _MON[s[:3]]
        rest = s[3:].strip()
        day, hms = rest.split(None, 1)
        hh, mm, ss = (int(x) for x in hms.split(":"))
        dt = datetime(now.year, mon, int(day), hh, mm, ss, tzinfo=timezone.utc)
        if dt - now > timedelta(days=1):  # Dec rolling over into Jan
            dt = dt.replace(year=now.year - 1)
        return dt
    except Exception:
        return None


def _parse_sd(s: str):
    """Light RFC5424 structured-data -> (dict, remainder)."""
    if s.startswith("-") and (len(s) == 1 or s[1] == " "):
        return {}, s[1:].lstrip()
    if not s.startswith("["):
        return {}, s
    out, i, n = {}, 0, len(s)
    while i < n and s[i] == "[":
        j = s.find("]", i)
        if j == -1:
            break
        chunk = s[i + 1:j]
        parts = chunk.split(" ", 1)
        sid = parts[0]
        kvs = {}
        if len(parts) > 1:
            for k, v in re.findall(r'(\w+)="([^"]*)"', parts[1]):
                kvs[k] = v
        out[sid] = kvs
        i = j + 1
    return out, s[i:].lstrip()


def _parse_cisco(text: str):
    m = _CISCO_RE.match(text)
    if m is None:
        return None
    sev = int(m.group("sev"))
    attrs = {"device_time": m.group("dts").lstrip("*.").strip()}
    if m.group("seq"):
        attrs["cisco_seq"] = m.group("seq")
    return {
        "host": m.group("host"),
        "program": f"%{m.group('fac')}-{m.group('sev')}-{m.group('code')}",
        "severity": _SYSLOG_TO_OTEL.get(sev),
        "severity_text": _SYSLOG_SEV_NAME.get(sev),
        "msg": m.group("msg").strip(),
        "attrs": attrs,
    }


def parse_syslog(raw: str, peer: str | None) -> dict:
    """Decode one syslog line into a normalized event dict. Never raises — an
    undecodable line still becomes a row (source=peer, whole line as body)."""
    now = datetime.now(timezone.utc)
    text = raw.strip()
    facility = severity = sevtext = program = None
    attrs: dict = {}

    m = _PRI_RE.match(text)
    if m:
        pri = int(m.group(1))
        facility = _FACILITY.get(pri >> 3, str(pri >> 3))
        sev = pri & 7
        severity = _SYSLOG_TO_OTEL.get(sev)
        sevtext = _SYSLOG_SEV_NAME.get(sev)
        text = text[m.end():]

    cisco = _parse_cisco(text)
    if cisco is not None:
        if cisco["severity"] is not None:
            severity, sevtext = cisco["severity"], cisco["severity_text"]
        return {
            "ts": now, "source": cisco["host"] or peer or "unknown", "facility": facility,
            "severity": severity, "severity_text": sevtext, "program": cisco["program"],
            "body": cisco["msg"], "attributes": cisco["attrs"],
            "raw": raw if len(raw) <= 64_000 else raw[:64_000],
        }

    ts = None
    host = None
    body = text

    if text[:2] == "1 ":  # RFC5424: "1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG"
        f = text[2:].split(" ", 5)
        if len(f) == 6:
            tstr, host, app, procid, msgid, rest = f
            ts = _parse_5424_ts(tstr)
            program = None if app == "-" else app
            host = None if host == "-" else host
            sd, body = _parse_sd(rest)
            if sd:
                attrs["sd"] = sd
            if procid not in ("-", ""):
                attrs["procid"] = procid
            if msgid not in ("-", ""):
                attrs["msgid"] = msgid
    else:
        m3 = _RFC3164_RE.match(text)
        if m3:
            ts = _parse_3164_ts(m3.group("ts"), now)
            host = m3.group("host")
            program = m3.group("tag")
            if m3.group("pid"):
                attrs["pid"] = m3.group("pid")
            body = m3.group("msg")

    return {
        "ts": ts or now, "source": host or peer or "unknown", "facility": facility,
        "severity": severity, "severity_text": sevtext, "program": program,
        "body": body, "attributes": attrs,
        "raw": raw if len(raw) <= 64_000 else raw[:64_000],
    }


# --- template mining: mask variable bits so one row covers a message shape ---
_MASKERS = [
    (re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"), "<*>"),  # uuid
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "<*>"),                  # mac
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<*>"),                      # ipv4(:port)
    (re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"), "<*>"),            # ipv6-ish
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<*>"),                                        # hex
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<*>"),                                      # long hex run
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<*>"),                                         # numbers
]
_COLLAPSE = re.compile(r"(<\*>)(\s+<\*>)+")


def mine_template(program: str | None, body: str | None) -> tuple[str, str]:
    """Return (fingerprint, template) for a message. Variable bits -> <*>."""
    t = body or ""
    for rx, repl in _MASKERS:
        t = rx.sub(repl, t)
    t = _COLLAPSE.sub(r"\1", t).strip()
    fp = hashlib.sha1(f"{program or ''}\x00{t}".encode("utf-8", "replace")).hexdigest()
    return fp, t


# Severity-word -> OTel number (for L2 verdicts / MCP inputs).
SEV_NUM = {"info": 9, "warn": 13, "warning": 13, "error": 17, "err": 17,
           "crit": 18, "critical": 18}
