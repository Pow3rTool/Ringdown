-- 2026-07-03 — L2 semantic-eval trace (additive migration).
--
-- Adds semantic_evals (one row per judge evaluation, fired or not — powers the
-- WebUI "eval" event kind) and refreshes ringdown_retention() so the new table
-- is pruned on the same window as events.
--
-- APPLY THIS DELTA — do NOT re-run the full ringdown/schema.sql against an
-- existing DB: it contains bare CREATE TRIGGER statements (no OR REPLACE) that
-- abort under psql ON_ERROR_STOP with "trigger already exists". This file is
-- safe/idempotent (IF NOT EXISTS + CREATE OR REPLACE) and re-runnable.
--
--   psql "$RINGDOWN_DB_DSN" -f scripts/migrations/2026-07-03-semantic-evals.sql
--
-- Run this BEFORE deploying the new collector/webui: the new webui stream reads
-- semantic_evals on connect, so the table must exist first. (The collector's
-- trace writes are wrapped best-effort and degrade quietly, but the webui isn't.)

BEGIN;

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
-- Added after first deploy: separate reasoning trace (re-runnable).
ALTER TABLE semantic_evals ADD COLUMN IF NOT EXISTS reasoning text;

-- Refresh retention so it also prunes semantic_evals (adds the final DELETE).
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
END $$;

COMMIT;
