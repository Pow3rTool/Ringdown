# Ringdown

Ingest logs, decide what matters, and notify the right responder — a human **or** an agent —
with enough context to act.

Ringdown is a syslog ingestion and alert-routing service. It normalizes incoming log events,
matches them against a rule engine (with an optional LLM-judged second pass for fuzzier
signals), and dispatches notifications through a pluggable set of targets.

> **Status:** early / work in progress. Interfaces and schema may change. Not yet packaged for
> general use — treat this as a reference implementation.

## Architecture

Two long-running processes share one Postgres database and never talk directly — they meet only
at the DB (rows plus `LISTEN/NOTIFY`):

```
syslog (UDP/TCP 514) → collector → Postgres ← control plane ← operators / agents
                          │  match rules                (CRUD rules & targets;
                          ▼                               a trigger NOTIFYs)
                     dispatch → pluggable targets (human push, agent hand-off, …)
```

- **`ringdown.collector`** — the hot path: ingest syslog, normalize and template-mine, store,
  match the in-memory ruleset, and dispatch. The ruleset refreshes on a Postgres `NOTIFY`, not
  per line. An optional LLM-judged loop handles signals that plain rules miss.
- **`ringdown.mcp_server`** — an authenticated control plane for querying the log store and
  managing alert rules and notification targets.

## Layout

```
ringdown/
  config.py         environment load + validation
  db.py             pooled DB access + the LISTEN/NOTIFY listener
  schema.sql        Postgres schema + NOTIFY triggers
  syslog_parse.py   RFC5424 / RFC3164 decode + template mining
  collector.py      hot path: ingest → match → dispatch
  ruleset.py        in-memory compiled ruleset (NOTIFY-refreshed)
  router.py         match + fan-out + coalesce
  incidents.py      dispatch coordinator: dedup / feed / throttle / fallback
  judge.py          optional LLM-judged loop
  mcp_server.py     authenticated control plane (query + CRUD)
  dispatch/         dispatcher interface + registry + target implementations
deploy/             systemd units
scripts/            database provisioning
tests/              test suite
```

## Design notes

- **Fail closed.** When a notification can't be delivered as intended, Ringdown falls back to a
  safe path rather than dropping the signal, and never escalates privilege to make a delivery
  succeed.
- **No raw bodies on shared channels.** Public/shared notification targets receive only a
  sanitized summary (rule, source, severity), never raw log lines.
- **Configuration is external.** All secrets and host-specific settings come from the
  environment; nothing sensitive lives in the tree. See `.env.example`.

## Getting started

Requires Postgres and Python 3.11+.

```bash
cp .env.example .env          # then fill in the values
sudo -u postgres bash scripts/provision-db.sh
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
pytest -q
```

See `deploy/` for the systemd units and `.env.example` for the full list of configuration
options.

## License

See [LICENSE](LICENSE).
