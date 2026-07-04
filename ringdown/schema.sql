-- Ringdown — log store + alert/target control plane (PostgreSQL 16 + pgvector)
-- =========================================================================
-- Successor to the Ringdown prototype's schema. The event spine (events / log_templates /
-- sources) is carried over verbatim (it earned its keep in the POC); the
-- alerting side is re-shaped for Ringdown's design:
--
--   * The hardcoded `channel` enum (ntfy|turnstone|both) is GONE. A rule now
--     binds one or more `targets` (rows in a typed, owned, pluggable target
--     registry) via `rule_targets`. Adding a new dispatcher type is a code
--     plugin + a target row, not a schema change.
--   * Rules gain owner/project scoping + router knobs (order, stop_on_match)
--     + L2 window semantics (window_kind, spike_lines).
--   * A dedup `alert_incidents` envelope keyed per (rule, target, source) so
--     fan-out to N targets keeps N independent stateful handles.
--   * An `audit` table for every rule/target CRUD + every dispatch.
--   * LISTEN/NOTIFY triggers so the collector refreshes its in-memory ruleset
--     on change instead of polling the DB per line.
--
-- Storage strategy is unchanged from the Ringdown prototype: events partitioned BY WEEK on ts
-- (retention = DETACH/DROP a week, not row-delete); BRIN(ts) + GIN(tsvector)
-- + btree; templates masked to one row/shape and embedded via pgvector.
-- =========================================================================

CREATE EXTENSION IF NOT EXISTS vector;

-- --- the log event spine (OTel-shaped, partitioned by week) ---------------
CREATE TABLE IF NOT EXISTS events (
    id            bigint        GENERATED ALWAYS AS IDENTITY,
    ts            timestamptz   NOT NULL,                 -- event time (parsed, else receipt)
    received_at   timestamptz   NOT NULL DEFAULT now(),   -- when Ringdown got it
    source        text          NOT NULL,                 -- device/host  (OTel resource: host.name)
    facility      text,                                   -- syslog facility name
    severity      smallint,                               -- OTel severity_number 1..24 (normalized)
    severity_text text,                                   -- original severity word (e.g. "err", "warning")
    program       text,                                   -- syslog app-name / process / OTel scope
    body          text          NOT NULL,                 -- the message            (OTel: body)
    attributes    jsonb         NOT NULL DEFAULT '{}',    -- parsed kv / RFC5424 SD  (OTel: attributes)
    raw           text,                                   -- original line, verbatim (never lose fidelity)
    template_id   bigint,                                 -- -> log_templates(id)    (enrichment/dedup)
    trace_id      text,                                   -- OTel correlation (future), usually NULL
    search        tsvector      GENERATED ALWAYS AS (to_tsvector('english', coalesce(body, ''))) STORED,
    PRIMARY KEY (id, ts)                                  -- PK must include the partition key
) PARTITION BY RANGE (ts);

CREATE INDEX IF NOT EXISTS events_ts_brin   ON events USING brin (ts);
CREATE INDEX IF NOT EXISTS events_src_ts    ON events (source, ts DESC);
CREATE INDEX IF NOT EXISTS events_search    ON events USING gin (search);
CREATE INDEX IF NOT EXISTS events_sev_ts    ON events (severity, ts DESC);
CREATE INDEX IF NOT EXISTS events_tmpl      ON events (template_id);

-- Idempotently create the weekly partition covering `at` (ISO week, Mon..Mon).
CREATE OR REPLACE FUNCTION ringdown_ensure_week(at timestamptz)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    wk_start date := (date_trunc('week', at))::date;
    wk_end   date := (date_trunc('week', at) + interval '7 days')::date;
    pname    text := format('events_%s', to_char(wk_start, 'IYYY_IW'));
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = pname) THEN
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
            pname, wk_start, wk_end);
    END IF;
END $$;

-- --- template mining: one row per distinct masked message -----------------
-- embedding dim 768 = a local sentence/bge/nomic embedder (override per model).
CREATE TABLE IF NOT EXISTS log_templates (
    id          bigint       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    fingerprint text         UNIQUE NOT NULL,
    template    text         NOT NULL,
    embedding   vector(768),
    first_seen  timestamptz  NOT NULL DEFAULT now(),
    last_seen   timestamptz  NOT NULL DEFAULT now(),
    hits        bigint       NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS log_templates_embed
    ON log_templates USING hnsw (embedding vector_cosine_ops);

-- --- discovered devices (JIT, no pre-registration) ------------------------
-- `active` is the "have we heard from it lately" flag. Retention flips it false
-- for a source unseen past the window; the collector flips it back true the
-- instant a line arrives again (so a quiet/decommed device hides itself, and a
-- device that comes back un-hides itself — no manual bookkeeping).
CREATE TABLE IF NOT EXISTS sources (
    source      text         PRIMARY KEY,
    label       text,
    kind        text,
    active      boolean      NOT NULL DEFAULT true,
    first_seen  timestamptz  NOT NULL DEFAULT now(),
    last_seen   timestamptz  NOT NULL DEFAULT now(),
    events      bigint       NOT NULL DEFAULT 0
);
-- migration for existing installs (the Ringdown prototype's table had no `active`)
ALTER TABLE sources ADD COLUMN IF NOT EXISTS active boolean NOT NULL DEFAULT true;

-- --- retention (SPEC: this is a monitoring plane, NOT a log archive) --------
-- Ringdown keeps a rolling window, not history. `keep_days` old:
--   * events   — DROP whole weekly partitions whose range is entirely past the
--     cutoff (partition drop, never row-delete — instant, no bloat, no vacuum).
--   * sources  — deactivate/hide any device unseen within the window (reversible;
--     the collector reactivates on the next line). Rows are kept (cheap, and the
--     first_seen/events history stays) — only the `active` flag is toggled.
-- Called on a daily tick by the collector (see collector.maintenance). Returns
-- the partitions it dropped so the caller can log them.
CREATE OR REPLACE FUNCTION ringdown_retention(keep_days int DEFAULT 90)
RETURNS TABLE(dropped_partition text) LANGUAGE plpgsql AS $$
DECLARE
    cutoff timestamptz := now() - make_interval(days => keep_days);
    r      record;
    hi     text;
BEGIN
    FOR r IN
        SELECT c.oid, c.relname, pg_get_expr(c.relpartbound, c.oid) AS bound
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'events'
    LOOP
        -- bound: FOR VALUES FROM ('...') TO ('<upper>'). Drop only when the
        -- partition's UPPER bound is already past the cutoff (fully expired).
        hi := substring(r.bound from $re$TO \('([^']+)'\)$re$);
        CONTINUE WHEN hi IS NULL;
        IF hi::timestamptz <= cutoff THEN
            EXECUTE format('DROP TABLE IF EXISTS %I', r.relname);
            dropped_partition := r.relname;
            RETURN NEXT;
        END IF;
    END LOOP;

    UPDATE sources SET active = false
     WHERE active AND last_seen < cutoff;

    -- semantic eval trace shares the monitoring window (not a partitioned table).
    DELETE FROM semantic_evals WHERE evaluated_at < cutoff;

    -- expired or revoked WebUI sessions (bounded by their own absolute_exp/revoked,
    -- NOT keep_days — a session cannot outlive RINGDOWN_SESSION_ABSOLUTE_CAP_DAYS).
    DELETE FROM webui_sessions WHERE revoked OR absolute_exp < now();
END $$;

-- === alerting control plane ===============================================

-- --- targets: the pluggable "how to reach a responder" registry -----------
-- Decoupled from any rule. Typed (ntfy | turnstone | webhook-template | …),
-- owned, and config is SENSITIVE (URLs / auth refs / topics) — the MCP
-- redacts `config` for non-owners. `identity_policy` says whose authority a
-- dispatch runs under:
--   run-as-owner — mint/redeem the rule owner's identity (turnstone OBO)
--   static-svc   — a fixed service identity carried in config
--   none         — unauthenticated fire-and-forget (ntfy public push)
CREATE TABLE IF NOT EXISTS targets (
    id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            text        NOT NULL,
    type            text        NOT NULL,                 -- dispatcher plugin key
    config          jsonb       NOT NULL DEFAULT '{}',    -- SENSITIVE: redact for non-owners
    identity_policy text        NOT NULL DEFAULT 'none'
                    CHECK (identity_policy IN ('run-as-owner', 'static-svc', 'none')),
    owner_oid       text,                                 -- Entra oid of the target's owner (human)
    owner_upn       text,
    owner_bot       text,                                 -- azp/appid of the registering agent (bot)
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS targets_name ON targets (name);

-- --- alert hooks: regex (L1) or semantic/plain-English (L2) ---------------
CREATE TABLE IF NOT EXISTS alert_rules (
    id               bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name             text        NOT NULL,
    kind             text        NOT NULL CHECK (kind IN ('regex', 'semantic')),
    pattern          text        NOT NULL,            -- regex source OR the NL condition
    instructions     text,                            -- per-rule triage guidance handed to the agent
    source_glob      text,
    min_severity     smallint,
    -- L2 windowing
    window_kind      text        NOT NULL DEFAULT 'sliding'
                     CHECK (window_kind IN ('sliding', 'tumbling')),
    window_seconds   integer     NOT NULL DEFAULT 300,
    spike_lines      integer,                          -- burst-of-N NEW lines -> judge early (L2)
    cooldown_seconds integer     NOT NULL DEFAULT 300, -- min gap feeding repeat matches to a handle
    -- router knobs
    rule_order       integer     NOT NULL DEFAULT 100, -- lower = evaluated first ("order" is reserved)
    stop_on_match    boolean     NOT NULL DEFAULT false,-- pf's `quick`: terminal-stop the router
    enabled          boolean     NOT NULL DEFAULT true,
    -- identity / ownership / scoping
    owner_user       text,                             -- turnstone user_id the hook RUNS AS (run-as-owner)
    project_id       text,                             -- turnstone project for team visibility
    created_by       text,                             -- Entra oid of the human the hook belongs to
    created_by_upn   text,                             -- UPN/preferred_username (-> turnstone user)
    created_by_bot   text,                             -- azp/appid of the registering agent (bot).
                                                        -- write-ownership is keyed on (created_by,
                                                        -- created_by_bot): agent2 acting as the SAME
                                                        -- human still can't CRUD agent1's rules
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_fired       timestamptz
);
CREATE INDEX IF NOT EXISTS alert_rules_enabled ON alert_rules (enabled, kind);
CREATE INDEX IF NOT EXISTS alert_rules_owner   ON alert_rules (created_by);

-- --- rule -> target bindings (fan-out; per-binding router knobs) ----------
CREATE TABLE IF NOT EXISTS rule_targets (
    rule_id       bigint      NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    target_id     bigint      NOT NULL REFERENCES targets(id)     ON DELETE CASCADE,
    target_order  integer     NOT NULL DEFAULT 100,
    stop_on_match boolean     NOT NULL DEFAULT false,
    PRIMARY KEY (rule_id, target_id)
);
CREATE INDEX IF NOT EXISTS rule_targets_target ON rule_targets (target_id);

-- --- firing history -------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_events (
    id          bigint       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id     bigint       REFERENCES alert_rules(id) ON DELETE CASCADE,
    target_id   bigint       REFERENCES targets(id)     ON DELETE SET NULL,
    fired_at    timestamptz  NOT NULL DEFAULT now(),
    source      text,
    summary     text,                                 -- rule- or LLM-generated "why you care"
    sample      jsonb        NOT NULL DEFAULT '{}',    -- handle + disposition + a snippet
    dedup_key   text,
    notified    boolean      NOT NULL DEFAULT false,
    disposition text                                  -- opened | fed | throttled | ntfy | fallback | error
);
CREATE INDEX IF NOT EXISTS alert_events_rule_ts ON alert_events (rule_id, fired_at DESC);
CREATE INDEX IF NOT EXISTS alert_events_dedup   ON alert_events (dedup_key, fired_at DESC);

-- --- incident dedup/state envelope (one open handle per rule+target+source) -
-- A fired hook opens ONE handle per dedup_key; subsequent matches FEED that
-- handle (stateful dispatchers) instead of opening a new one. Reuse is gated
-- by the reuse-TTL (last_event_at) so a recurrence after quiet reopens fresh.
-- `handle` is the dispatcher's opaque handle (turnstone: ws_id; ntfy: '').
CREATE TABLE IF NOT EXISTS alert_incidents (
    dedup_key     text         PRIMARY KEY,            -- "<rule_id>:<target_id>:<source>"
    rule_id       bigint       REFERENCES alert_rules(id) ON DELETE CASCADE,
    target_id     bigint       REFERENCES targets(id)     ON DELETE CASCADE,
    source        text,
    handle        text,                                -- dispatcher handle (turnstone ws_id, …)
    owner_user    text,                                -- identity the handle was opened as
    opened_at     timestamptz  NOT NULL DEFAULT now(),
    last_event_at timestamptz  NOT NULL DEFAULT now(),
    last_fed_at   timestamptz,
    event_count   bigint       NOT NULL DEFAULT 1,
    status        text         NOT NULL DEFAULT 'open'  -- open | closed
);
CREATE INDEX IF NOT EXISTS alert_incidents_rule ON alert_incidents (rule_id, last_event_at DESC);

-- --- audit: every rule/target CRUD + every dispatch (chmod 600 on disk too) -
CREATE TABLE IF NOT EXISTS audit (
    id         bigint       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts         timestamptz  NOT NULL DEFAULT now(),
    actor_oid  text,                                   -- Entra oid (or 'collector' for dispatch)
    actor_upn  text,
    action     text         NOT NULL,                  -- e.g. register_alert, delete_target, dispatch
    detail     jsonb        NOT NULL DEFAULT '{}',
    ok         boolean      NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts DESC);

-- --- WebUI server-side sessions (OIDC refresh-token backing) ---------------
-- The admin WebUI cookie carries only an opaque `sid`; the session lives here so
-- we can hold the Entra refresh token (encrypted at rest, AES-256-GCM, key from
-- RINGDOWN_SESSION_ENC_KEY) and silently re-validate the operator without the
-- full interactive Entra flow. Every refresh re-checks the Ringdown.Admin role
-- and rotates the stored token. `absolute_exp` is the hard ceiling
-- (RINGDOWN_SESSION_ABSOLUTE_CAP_DAYS); any refresh error / revoke / expiry ->
-- no session -> interactive login. Pruned by ringdown_retention().
CREATE TABLE IF NOT EXISTS webui_sessions (
    sid            text         PRIMARY KEY,             -- opaque; the cookie value
    oid            text,                                 -- Entra object id
    upn            text,                                 -- preferred_username
    name           text,                                 -- display name
    refresh_enc    bytea        NOT NULL,                -- AES-256-GCM ciphertext of the refresh token
    refresh_nonce  bytea        NOT NULL,                -- 12-byte GCM nonce
    access_exp     timestamptz  NOT NULL,                -- current access-token expiry (drives refresh)
    absolute_exp   timestamptz  NOT NULL,                -- hard ceiling; session cannot outlive this
    last_seen      timestamptz  NOT NULL DEFAULT now(),  -- sliding activity marker
    revoked        boolean      NOT NULL DEFAULT false,  -- logout / failed refresh / lost role
    created_at     timestamptz  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webui_sessions_gc ON webui_sessions (absolute_exp) WHERE NOT revoked;

-- --- semantic (L2) evaluation trace ---------------------------------------
-- One row PER judge evaluation — whether or not it fired. This is the audit
-- trail for the LLM tier: it captures EXACTLY what the model was shown
-- (`summary_sent`, the deduped window digest) and what it returned (`llm_raw`,
-- the raw reply incl. reasoning; plus the parsed verdict/why). It answers
-- "why did this semantic rule fire (or not)?" and "how often is the LLM even
-- called?" — neither of which the fire-only history (alert_events) can.
-- Powers the WebUI "eval" event kind (click-in detail). Not a log archive:
-- pruned by ringdown_retention() on the same window as events.
CREATE TABLE IF NOT EXISTS semantic_evals (
    id             bigint       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id        bigint       REFERENCES alert_rules(id) ON DELETE CASCADE,
    evaluated_at   timestamptz  NOT NULL DEFAULT now(),
    source         text,                                 -- top source in the window (label only)
    trigger_kind   text         NOT NULL,                -- 'interval' | 'spike' (why it ran now)
    window_from_id bigint,                               -- events considered: id in (from_id, to_id]
    window_to_id   bigint,
    event_count    integer      NOT NULL DEFAULT 0,      -- lines in the evaluated window
    elapsed_s      real,                                 -- seconds since this rule's prior eval
    fired          boolean      NOT NULL DEFAULT false,
    severity       text,                                 -- verdict severity (when fired)
    why            text,                                 -- verdict one-liner
    llm_ok         boolean      NOT NULL DEFAULT true,    -- call succeeded AND a verdict parsed
    latency_ms     integer,                              -- LLM round-trip
    model          text,
    summary_sent   text,                                 -- EXACTLY what the LLM saw (window digest)
    reasoning      text,                                 -- separate reasoning_content trace (reasoning models)
    llm_raw        text                                  -- the answer reply (`content`) we parse the verdict from
);
CREATE INDEX IF NOT EXISTS semantic_evals_rule_ts ON semantic_evals (rule_id, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS semantic_evals_ts      ON semantic_evals (evaluated_at DESC);
CREATE INDEX IF NOT EXISTS semantic_evals_fired   ON semantic_evals (fired, evaluated_at DESC);

-- === live rule propagation: LISTEN/NOTIFY spine ================
-- Any writer that touches a rule/target/binding fires NOTIFY on the
-- 'rules_changed' channel; the collector LISTENs and refreshes its in-memory
-- compiled ruleset (targeted or full reload — the ruleset is small). Zero
-- per-line DB reads. A trigger (not just app-level NOTIFY) means EVERY writer
-- — MCP, a manual psql edit, a migration — is caught.
CREATE OR REPLACE FUNCTION ringdown_notify_rules_changed()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    payload text;
    row_id  text;
BEGIN
    row_id  := COALESCE((to_jsonb(NEW)->>'id'), (to_jsonb(OLD)->>'id'),
                        (to_jsonb(NEW)->>'rule_id'), (to_jsonb(OLD)->>'rule_id'), '');
    payload := json_build_object('table', TG_TABLE_NAME, 'op', TG_OP, 'id', row_id)::text;
    PERFORM pg_notify('rules_changed', payload);
    RETURN NULL;  -- AFTER trigger; return value ignored
END $$;

DROP TRIGGER IF EXISTS trg_notify_rules   ON alert_rules;
DROP TRIGGER IF EXISTS trg_notify_targets ON targets;
DROP TRIGGER IF EXISTS trg_notify_binds   ON rule_targets;

CREATE TRIGGER trg_notify_rules   AFTER INSERT OR UPDATE OR DELETE ON alert_rules
    FOR EACH ROW EXECUTE FUNCTION ringdown_notify_rules_changed();
CREATE TRIGGER trg_notify_targets AFTER INSERT OR UPDATE OR DELETE ON targets
    FOR EACH ROW EXECUTE FUNCTION ringdown_notify_rules_changed();
CREATE TRIGGER trg_notify_binds   AFTER INSERT OR UPDATE OR DELETE ON rule_targets
    FOR EACH ROW EXECUTE FUNCTION ringdown_notify_rules_changed();
