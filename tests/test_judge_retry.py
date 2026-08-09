from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ringdown import judge as judge_module
from ringdown.judge import SemanticJudge


class FakeCoordinator:
    def __init__(self):
        self.notices = []

    async def notify_ops(self, title, body, *, tags=None):
        self.notices.append((title, body, tags))
        return True


class FakeRouter:
    @staticmethod
    def _follow_up(_rule, _event):
        return ""


def _rule():
    return {
        "id": 7,
        "name": "semantic-test",
        "pattern": "something is wrong",
        "instructions": "",
        "source_glob": "",
        "min_severity": None,
        "window_seconds": 0,
        "spike_lines": 1,
        "owner_user": "",
        "targets": [{"id": 3}],
    }


def _event(event_id):
    return {
        "id": event_id,
        "ts": datetime(2026, 8, 9, 1, 2, 3, tzinfo=timezone.utc),
        "source": "router-1",
        "severity": 17,
        "severity_text": "err",
        "program": "test",
        "body": f"event {event_id}",
        "template_id": 1,
    }


async def test_failure_alerts_immediately_then_at_most_once_per_interval(monkeypatch):
    clock = {"now": 100.0}
    monkeypatch.setattr(judge_module.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(judge_module.config, "SEMANTIC_OUTAGE_ALERT_S", 86400)
    coord = FakeCoordinator()
    judge = SemanticJudge(None, coord, FakeRouter(), None)

    await judge._track_llm_health(False)
    assert len(coord.notices) == 1
    assert "retained and will retry" in coord.notices[0][1]

    clock["now"] += 60
    await judge._track_llm_health(False)
    assert len(coord.notices) == 1

    clock["now"] += 86400
    await judge._track_llm_health(False)
    assert len(coord.notices) == 2

    await judge._track_llm_health(True)
    assert len(coord.notices) == 3
    assert "recovered" in coord.notices[-1][0]


async def test_failed_window_is_retried_before_checkpoint_advances(monkeypatch):
    events = [_event(1), _event(2)]
    fetch_starts = []
    checkpoints = []

    async def fake_fetchone(_pool, sql, params=()):
        assert "count(*)" in sql
        return {"c": len([e for e in events if e["id"] > params[0]])}

    async def fake_fetch(_pool, sql, params=()):
        assert "ORDER BY id ASC LIMIT 5000" in sql
        fetch_starts.append(params[0])
        return [e for e in events if e["id"] > params[0]][:5000]

    async def fake_execute(_pool, sql, params=()):
        assert "UPDATE semantic_rule_state" in sql
        checkpoints.append(params[0])
        return {"last_event_id": params[0]}

    monkeypatch.setattr(judge_module.db, "fetchone", fake_fetchone)
    monkeypatch.setattr(judge_module.db, "fetch", fake_fetch)
    monkeypatch.setattr(judge_module.db, "execute", fake_execute)
    monkeypatch.setattr(judge_module.config, "SEMANTIC_MIN_INTERVAL", 0)
    monkeypatch.setattr(judge_module.config, "SEMANTIC_MAX_PER_MIN", 0)
    monkeypatch.setattr(judge_module.config, "SEMANTIC_TICK", 30)
    monkeypatch.setattr(judge_module.config, "SEMANTIC_OUTAGE_ALERT_S", 86400)

    coord = FakeCoordinator()
    judge = SemanticJudge(None, coord, FakeRouter(), None)
    judge._seen[7] = 0
    judge._last[7] = 0
    judge._rules_with_targets = lambda: _async_value([_rule()])
    results = iter([
        (None, "ConnectError", "", False, 2),
        ({"fire": False, "why": "quiet"}, '{"fire":false}', "", True, 3),
    ])

    async def fake_llm(_condition, _summary):
        return next(results)

    traces = []

    async def fake_trace(*args):
        traces.append(args)

    judge._judge_llm = fake_llm
    judge._trace = fake_trace

    await judge._eval()
    assert judge._seen[7] == 0
    assert checkpoints == []

    judge._retry_after[7] = 0
    await judge._eval()
    assert fetch_starts == [0, 0]
    assert [trace[10] for trace in traces] == [False, True]
    assert checkpoints == [2]
    assert judge._seen[7] == 2


async def test_catchup_reads_oldest_batches_without_skipping(monkeypatch):
    events = [_event(i) for i in range(1, 5003)]
    batches = []

    async def fake_fetchone(_pool, sql, params=()):
        return {"c": len([e for e in events if e["id"] > params[0]])}

    async def fake_fetch(_pool, sql, params=()):
        batch = [e for e in events if e["id"] > params[0]][:5000]
        batches.append((batch[0]["id"], batch[-1]["id"]))
        return batch

    async def fake_execute(_pool, _sql, params=()):
        return {"last_event_id": params[0]}

    monkeypatch.setattr(judge_module.db, "fetchone", fake_fetchone)
    monkeypatch.setattr(judge_module.db, "fetch", fake_fetch)
    monkeypatch.setattr(judge_module.db, "execute", fake_execute)
    monkeypatch.setattr(judge_module.config, "SEMANTIC_MIN_INTERVAL", 0)
    monkeypatch.setattr(judge_module.config, "SEMANTIC_MAX_PER_MIN", 0)

    judge = SemanticJudge(None, FakeCoordinator(), FakeRouter(), None)
    judge._seen[7] = 0
    judge._last[7] = 0
    judge._rules_with_targets = lambda: _async_value([_rule()])

    async def successful_llm(_condition, _summary):
        return {"fire": False, "why": "quiet"}, '{"fire":false}', "", True, 1

    judge._judge_llm = successful_llm
    judge._trace = _noop

    await judge._eval()
    judge._last[7] = 0
    await judge._eval()

    assert batches == [(1, 5000), (5001, 5002)]
    assert judge._seen[7] == 5002


async def test_upgrade_bootstrap_resumes_at_last_success_before_failed_window(monkeypatch):
    stamp = datetime(2026, 8, 9, tzinfo=timezone.utc)

    async def fake_fetchone(_pool, sql, _params=()):
        if "FROM semantic_rule_state" in sql:
            return None
        if "ORDER BY id DESC LIMIT 1" in sql and "AND llm_ok" not in sql:
            return {"llm_ok": False, "window_from_id": 200, "window_to_id": 300,
                    "evaluated_at": stamp}
        if "AND llm_ok" in sql:
            return {"window_to_id": 100, "evaluated_at": stamp}
        raise AssertionError(sql)

    inserted = []

    async def fake_execute(_pool, sql, params=()):
        assert "INSERT INTO semantic_rule_state" in sql
        inserted.append(params)
        return {"last_event_id": params[1], "last_evaluated_at": params[2]}

    monkeypatch.setattr(judge_module.db, "fetchone", fake_fetchone)
    monkeypatch.setattr(judge_module.db, "execute", fake_execute)

    judge = SemanticJudge(None, FakeCoordinator(), FakeRouter(), None)
    brand_new = await judge._ensure_rule_state(7, "", [], stamp.timestamp())

    assert brand_new is False
    assert inserted[0][1] == 100
    assert judge._seen[7] == 100


async def _async_value(value):
    return value


async def _noop(*_args, **_kwargs):
    return None
