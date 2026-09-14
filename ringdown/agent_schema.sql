-- Additive stateful-dispatch migration. Stateless notification behavior stays
-- in alert_incidents; agent handles are never overwritten on TTL expiry.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS group_by text NOT NULL
    DEFAULT 'host' CHECK (group_by IN ('host', 'rule'));

CREATE TABLE IF NOT EXISTS agent_workstreams (
    handle text PRIMARY KEY,
    rule_id bigint REFERENCES alert_rules(id) ON DELETE SET NULL,
    target_id bigint REFERENCES targets(id) ON DELETE SET NULL,
    target_type text NOT NULL DEFAULT 'turnstone',
    source text,
    group_source text,
    dedup_key text NOT NULL,
    owner_user text NOT NULL DEFAULT '',
    project_id text NOT NULL DEFAULT '',
    created_by_upn text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('opening','open','uncertain','closed')),
    opened_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz,
    checked_at timestamptz,
    last_sent_at timestamptz,
    last_state text,
    last_detail text NOT NULL DEFAULT '',
    seeded boolean NOT NULL DEFAULT false,
    attempted boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS agent_workstreams_active ON agent_workstreams(status, rule_id, target_id);
ALTER TABLE agent_workstreams ADD COLUMN IF NOT EXISTS group_source text;

CREATE TABLE IF NOT EXISTS agent_pending (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id bigint NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
    rule_id bigint NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    target_id bigint NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    dedup_key text NOT NULL,
    assigned_handle text REFERENCES agent_workstreams(handle),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    available_at timestamptz NOT NULL DEFAULT now(),
    attempts int NOT NULL DEFAULT 0,
    last_detail text NOT NULL DEFAULT 'waiting for dispatch'
);
CREATE INDEX IF NOT EXISTS agent_pending_group ON agent_pending(dedup_key, id);
ALTER TABLE agent_pending ADD COLUMN IF NOT EXISTS assigned_handle text REFERENCES agent_workstreams(handle);

-- Import every known historical handle, including those the old TTL logic
-- overwrote. Unknown/deleted/private handles require reconciliation, not a
-- guessed free slot. Re-running migration must NEVER reopen a closed row.
INSERT INTO agent_workstreams
    (handle, rule_id, target_id, source, dedup_key, owner_user, project_id,
     created_by_upn, opened_at, last_sent_at, seeded, attempted)
SELECT DISTINCT ON (e.sample->>'handle')
    e.sample->>'handle', e.rule_id, e.target_id, e.source, coalesce(e.dedup_key, ''),
    coalesce(i.owner_user, r.owner_user, ''), coalesce(r.project_id, t.project_id, ''),
    coalesce(r.created_by_upn, ''), e.fired_at, e.fired_at, true, true
FROM alert_events e JOIN targets t ON t.id=e.target_id
JOIN alert_rules r ON r.id=e.rule_id
LEFT JOIN alert_incidents i ON i.handle=e.sample->>'handle'
WHERE t.type='turnstone' AND e.disposition='opened' AND e.sample->>'handle' <> ''
ORDER BY e.sample->>'handle', e.fired_at DESC
ON CONFLICT (handle) DO NOTHING;

INSERT INTO agent_workstreams
    (handle, rule_id, target_id, source, dedup_key, owner_user, project_id,
     created_by_upn, opened_at, last_sent_at, seeded, attempted)
SELECT i.handle, i.rule_id, i.target_id, i.source, i.dedup_key,
    coalesce(i.owner_user, r.owner_user, ''), coalesce(r.project_id, t.project_id, ''),
    coalesce(r.created_by_upn, ''), i.opened_at, i.last_fed_at, true, true
FROM alert_incidents i JOIN targets t ON t.id=i.target_id
JOIN alert_rules r ON r.id=i.rule_id
WHERE t.type='turnstone' AND coalesce(i.handle,'') <> ''
ON CONFLICT (handle) DO NOTHING;

UPDATE agent_workstreams SET group_source=regexp_replace(dedup_key, '^[^:]*:[^:]*:', '')
WHERE group_source IS NULL AND dedup_key ~ '^[0-9]+:[0-9]+:';
