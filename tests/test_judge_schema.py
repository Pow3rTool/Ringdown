from __future__ import annotations

from ringdown.judge import (
    SemanticJudge,
    VERDICT_RESPONSE_FORMAT,
    VERDICT_SCHEMA,
    _extract_verdict,
)


class FakeCoordinator:
    pass


class FakeRouter:
    pass


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "choices": [{
                "message": {
                    "content": '{"fire":false,"severity":"info","why":"quiet"}',
                },
            }],
        }


class CapturingHttp:
    def __init__(self):
        self.calls = []

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


async def test_semantic_judge_supplies_provider_and_nexus_verdict_schema():
    http = CapturingHttp()
    judge = SemanticJudge(None, FakeCoordinator(), FakeRouter(), http)

    verdict, content, reasoning, transport_ok, output_ok, _ms = await judge._judge_llm(
        "device is unhealthy",
        "1 events over 00:00:00–00:00:01Z",
    )

    assert transport_ok is True
    assert output_ok is True
    assert verdict == {"fire": False, "severity": "info", "why": "quiet"}
    assert content == '{"fire":false,"severity":"info","why":"quiet"}'
    assert reasoning == ""

    assert len(http.calls) == 1
    _url, call = http.calls[0]
    payload = call["json"]
    assert payload["response_format"] == VERDICT_RESPONSE_FORMAT
    assert payload["response_format"] == {
        "type": "json_schema",
        "json_schema": {
            "name": "ringdown_verdict",
            "strict": True,
            "schema": VERDICT_SCHEMA,
        },
    }
    assert payload["nexus_schema_kind"] == "json_schema"
    assert payload["nexus_schema"] == VERDICT_SCHEMA
    assert payload["nexus_schema"] == {
        "type": "object",
        "properties": {
            "fire": {"type": "boolean"},
            "severity": {"type": "string", "enum": ["info", "warn", "crit"]},
            "why": {"type": "string"},
        },
        "required": ["fire", "severity", "why"],
        "additionalProperties": False,
    }


class StaticResponse(FakeResponse):
    def __init__(self, message):
        self.message = message

    def json(self):
        return {"choices": [{"message": self.message}]}


class StaticHttp:
    def __init__(self, message):
        self.response = StaticResponse(message)

    async def post(self, _url, **_kwargs):
        return self.response


async def test_semantic_judge_accepts_reasoning_alias_when_content_is_empty():
    judge = SemanticJudge(None, FakeCoordinator(), FakeRouter(), StaticHttp({
        "content": "",
        "reasoning": '{"fire":true,"severity":"crit","why":"power failed"}',
    }))

    verdict, content, reasoning, transport_ok, output_ok, _ms = await judge._judge_llm(
        "device is unhealthy",
        "power supply failure",
    )

    assert transport_ok is True
    assert output_ok is True
    assert content == ""
    assert reasoning == '{"fire":true,"severity":"crit","why":"power failed"}'
    assert verdict == {"fire": True, "severity": "crit", "why": "power failed"}


def test_verdict_parser_rejects_values_outside_the_strict_schema():
    assert _extract_verdict('{"fire":"false","severity":"info","why":"quiet"}') is None
    assert _extract_verdict('{"fire":false,"severity":"debug","why":"quiet"}') is None
    assert _extract_verdict('{"fire":false,"severity":"info"}') is None
    assert _extract_verdict(
        '{"fire":false,"severity":"info","why":"quiet","extra":true}'
    ) is None
