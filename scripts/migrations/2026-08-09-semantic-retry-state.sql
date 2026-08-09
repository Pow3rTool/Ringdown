-- 2026-08-09 — durable L2 semantic-window checkpoints.
--
-- The collector populates this table lazily. On first startup it uses the
-- semantic_evals audit trail to resume an outstanding failed window; a rule with
-- no evaluation history keeps the established future-events-only baseline.

BEGIN;

CREATE TABLE IF NOT EXISTS semantic_rule_state (
    rule_id           bigint      PRIMARY KEY REFERENCES alert_rules(id) ON DELETE CASCADE,
    last_event_id     bigint      NOT NULL,
    last_evaluated_at timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL DEFAULT now()
);

COMMIT;
