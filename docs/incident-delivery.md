# Incident delivery

Ringdown queues stateful targets in PostgreSQL. Turnstone is unchanged.

## Configuration

- `register_alert(..., group_by="host")` is the default: separate incidents per host.
- `update_alert(rule_id=your_rule_id, group_by="rule")` groups all hosts matching that rule,
  separately per target, owner and project. This is appropriate for an SSH-login storm.
- `list_alerts` includes `group_by`. Existing semantic rules retain their previous
  cross-source window grouping. Stateless ntfy notification throttling is unchanged.
- `RINGDOWN_MAX_ACTIVE_WORKSTREAMS=4` counts all unclosed Ringdown agent chats,
  including idle chats, pending creation and uncertain outcomes. Allowed range: 1–4.
- `RINGDOWN_FEED_INTERVAL=60` batches repeats instead of discarding them.
- `RINGDOWN_DISPATCH_BATCH_SIZE=20` caps events per follow-up; messages also have a
  soft 12,000-character bound (a single larger event is kept intact).
- `RINGDOWN_DISPATCH_POLL_INTERVAL=10` controls delivery ticks. Lifecycle checks
  also run without incoming alerts. Active chats are checked roughly every 30s,
  and again before delivery. The old reuse TTL now applies only to stateless targets.
- The existing per-minute global opening ceiling is also retained, now in Postgres.

Use the desired rule ID returned by `list_alerts` for `your_rule_id` above.
Rule edits hot-reload through the existing database notification mechanism.
Changing grouping to `rule` adopts a suitable existing chat; it does not close
other already-open host chats. Those still count until closed in Turnstone.

## Closing and backpressure

Close the workstream in Turnstone to resolve the incident. Ringdown reads the
persisted `closed`/`deleted` state, without opening the workstream. Waiting events
assigned to it at or before the persisted closure timestamp are marked `resolved`.
Later arrivals can open a new incident, subject to capacity. Unknown timestamps
fall back to the time closure is observed. An unclosed but unloaded chat is NOT
automatically reopened or replaced; deliveries wait until its lifecycle is clear.

At capacity, new groups wait FIFO in Ringdown; existing chats still receive
batched follow-ups. Disabling or unbinding a rule cancels its pending deliveries,
but does not close its existing chats or free their slots.

Turnstone's HTTP-200 `queue_full` is a refusal, not delivery success. Ringdown
retains and retries the batch. `ok` and `queued` are acceptance, not proof the
agent finished processing it. Accepted messages are then Turnstone's responsibility.

## Visibility

The read-only MCP tool `dispatch_status` reports:

- Active workstreams, limit, lifecycle check timestamps and last send result.
- Pending event/group counts, oldest-event times and waiting reasons.
- `turnstone_queued_messages: null`: the current supported API does not expose
  exact remote queue depth. Ringdown's pending events are NOT that number.

`agent_pending` is the durable outbox; `agent_workstreams` retains every tracked
handle, including historical handles overwritten by the former TTL logic.
`alert_events` records `queued`, `opened`, `fed`, `resolved` or `cancelled`.
Delivered/resolved outbox entries are removed; their firing history remains.
Pending entries do not silently expire, so monitor backlog growth during a
prolonged outage. No target credentials are copied into queued payloads.

## Failure semantics and security

A PostgreSQL advisory lock serializes scheduler admission across replicas. Each
workstream ID is committed before creation. An ambiguous creation response holds
that slot and is reconciled with a metadata-only read; Ringdown never draws a
replacement ID merely because a request timed out. A confirmed refusal can retry
the same reservation. A crash immediately before the HTTP request may therefore
leave an uncertain reservation requiring operator reconciliation: safety wins
over silently generating duplicate agents.

An ambiguous *send* can repeat a batch in the same chat. Event IDs and stable
batch correlation IDs are included, but this is **at-least-once**, not exactly-once
delivery. Turnstone's `client_send_id` is correlation, not durable idempotency.

All calls remain owner-scoped. The existing metadata endpoint
`/v1/api/cluster/ws/{id}/detail?limit=0` requires `admin.cluster.inspect` on that
identity. Missing permission, timeouts and 404 are unknown, not closure (404 can
mask a private project). Do not use the routed detail endpoint for polling: it
can rehydrate a closed workstream. Changed owner/project bindings defer old
pending payloads for explicit reconciliation rather than borrowing credentials.

## Deployment and rollback

Run `python -m ringdown.migrate` before restarting collector/MCP/webui. Migration
is additive and idempotent; it imports all known historical handles. Inspect
legacy unknowns before rollout—confirm missing handles against authoritative
Turnstone storage, never treat a masked API 404 as deletion. Existing over-cap
chats are not killed; admissions wait until enough are closed.

Rollback: stop the new collector, retain the database/outbox, then pin the prior
image. The old collector does not drain the new outbox and lacks the four-chat
cap, so pause stateful rules if rolling back during a storm. Restore the new
release to drain retained events. Do not delete queue tables during rollback.

## Tests

`python -m pytest -q` runs unit tests. Set `RINGDOWN_TEST_DSN` to a **disposable**
PostgreSQL database to include isolated-schema concurrency/restart/migration
tests. Run the release migration twice on a disposable pgvector-enabled database
to check the complete fresh-install and idempotent-upgrade path.
