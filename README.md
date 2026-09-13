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
syslog (UDP/TCP 514) ─┐
                      ├→ collector → ingress filters → Postgres ← control plane
OTLP/HTTP JSON (4318) ┘
                                              │         ↑       operators / agents
                                              │ match rules     (CRUD filters/rules/targets;
                                              ▼                  triggers NOTIFY)
                     dispatch → pluggable targets (human push, agent hand-off, …)
```

- **`ringdown.collector`** — the hot path: ingest syslog and OTLP logs, normalize, discard centrally managed
  routine noise, template-mine and store accepted events, match the in-memory ruleset, and
  dispatch. Filter/rule sets refresh on Postgres `NOTIFY`, not per line. An optional LLM-judged
  loop handles signals that plain rules miss.
- **`ringdown.mcp_server`** — an authenticated control plane for querying the log store and
  managing global ingress filters, alert rules, and notification targets.
- **`ringdown.webui`** — the admin live tail plus ingress-filter CRUD, historical preview, and
  confirmation-gated bounded purge.

## Layout

```
ringdown/
  config.py         environment load + validation
  db.py             pooled DB access + the LISTEN/NOTIFY listener
  schema.sql        Postgres schema + NOTIFY triggers
  migrate.py        transactional idempotent schema runner
  syslog_parse.py   RFC5424 / RFC3164 decode + template mining
  filters.py        RE2/substring ingress matching + preview/purge helpers
  collector.py      hot path: ingest → filter → store → match → dispatch
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
- **Durable semantic catch-up.** L2 windows are checkpointed per rule only after a successful
  verdict. Inference failures retry with backoff and retained events are replayed oldest-first
  after recovery, including across collector restarts.
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

The collector accepts standard OTLP/HTTP JSON log exports at `POST /v1/logs`.
Ingress is fail-closed to `RINGDOWN_OTLP_ALLOWED_CIDRS`, uses the socket peer
address (never forwarding headers), and shares syslog's bounded queue, filters,
storage, and routing path. Defaults allow only IPv4 and IPv6 loopback. Configure
your trusted exporter subnets explicitly in the deployment environment; private
address space is not implicitly trusted. This is network trust, not workload
identity; use TLS client authentication when exposing the listener beyond a
trusted network. Protobuf OTLP is not enabled yet, so exporters must select the
OTLP/HTTP JSON protocol.

The complete OTLP attribute map remains stored for database forensics. Rules,
the semantic judge, MCP search results, and the WebUI expose only a bounded
allowlist of operational application and Netdata fields so arbitrary exporter data is
not promoted into alerts or agent context.

Apply all schemas before deploying a version that introduces schema changes:

```bash
python -m ringdown.migrate
```

The schema is idempotent and applied transactionally; one-time data migrations are tracked in
`ringdown_schema_migrations`.
Historical filter purges use bounded batches and make deleted space reusable by PostgreSQL.
Returning that space to the operating system still requires a separately scheduled partition
rewrite or `VACUUM FULL`.

## Incident grouping and workstream limits

Agent incidents default to per-host grouping. Set an alert's `group_by="rule"`
to collect a cross-host storm into one workstream per target/owner/project.
Ringdown allows at most four unclosed incident workstreams, queues excess events
durably, batches follow-ups, and recognizes closure in Turnstone automatically.
The `dispatch_status` MCP tool reports capacity and pending-event counts.
See [incident delivery](docs/incident-delivery.md) for configuration, failure
semantics, migration, and rollback. No Turnstone changes are required.

## License

See [LICENSE](LICENSE).
