from datetime import datetime, timezone
import json
import os
import subprocess
import sys

import pytest

from ringdown.otlp import OtlpPayloadError, allowed_networks, parse_otlp_json, peer_allowed


def av_string(value):
    return {"stringValue": value}


def test_peer_allowlist_uses_transport_address_and_handles_ipv4_mapped_ipv6():
    networks = allowed_networks([
        "127.0.0.0/8", "192.0.2.0/24", "198.51.100.0/25", "2001:db8::/32",
    ])
    assert peer_allowed("192.0.2.10", networks)
    assert peer_allowed("198.51.100.20", networks)
    assert peer_allowed("::ffff:192.0.2.30", networks)
    assert peer_allowed("2001:db8::1", networks)
    assert not peer_allowed("198.51.100.130", networks)
    assert not peer_allowed("203.0.113.7", networks)
    assert not peer_allowed(None, networks)


@pytest.mark.parametrize("override,expected", [
    (None, ["127.0.0.0/8", "::1/128"]),
    ("192.0.2.0/24,2001:db8::/32", ["192.0.2.0/24", "2001:db8::/32"]),
])
def test_otlp_trust_defaults_to_loopback_and_accepts_explicit_configuration(override, expected):
    env = os.environ.copy()
    env.pop("RINGDOWN_OTLP_ALLOWED_CIDRS", None)
    if override is not None:
        env["RINGDOWN_OTLP_ALLOWED_CIDRS"] = override
    result = subprocess.run([
        sys.executable, "-c",
        "import json; from ringdown.config import OTLP_ALLOWED_CIDRS; "
        "print(json.dumps(OTLP_ALLOWED_CIDRS))",
    ], env=env, check=True, capture_output=True, text=True)
    assert json.loads(result.stdout) == expected


def test_otlp_json_normalizes_resource_scope_record_and_transport_identity():
    ts_ns = 1_788_900_000_123_456_789
    payload = {
        "resourceLogs": [{
            "resource": {"attributes": [
                {"key": "host.name", "value": av_string("app-host.example.test")},
                {"key": "service.name", "value": av_string("example-app")},
                {"key": "service.instance.id", "value": av_string("example-app-a")},
            ]},
            "scopeLogs": [{
                "scope": {"name": "pino", "version": "9.5.0"},
                "logRecords": [{
                    "timeUnixNano": str(ts_ns),
                    "severityNumber": 17,
                    "severityText": "ERROR",
                    "body": av_string("provider request failed"),
                    "attributes": [
                        {"key": "provider", "value": av_string("example-provider")},
                        {"key": "request.id", "value": {"intValue": "123"}},
                    ],
                    "traceId": "0123456789abcdef0123456789abcdef",
                }],
            }],
        }],
    }
    event = parse_otlp_json(payload, "192.0.2.10")[0]
    assert event["source"] == "app-host.example.test"
    assert event["program"] == "example-app"
    assert event["severity"] == 17
    assert event["severity_text"] == "ERROR"
    assert event["body"] == "provider request failed"
    assert event["attributes"]["provider"] == "example-provider"
    assert event["attributes"]["request.id"] == 123
    assert event["attributes"]["ringdown.peer.ip"] == "192.0.2.10"
    assert event["attributes"]["resource"]["service.instance.id"] == "example-app-a"
    assert event["attributes"]["scope"]["name"] == "pino"
    assert event["attributes"]["otel.traceId"].startswith("012345")
    assert event["ts"] == datetime.fromtimestamp(ts_ns / 1_000_000_000, tz=timezone.utc)


def test_otlp_json_rejects_malformed_and_over_limit_envelopes():
    with pytest.raises(OtlpPayloadError):
        parse_otlp_json({"resourceLogs": {}}, "127.0.0.1")
    payload = {"resourceLogs": [{"scopeLogs": [{"logRecords": [{}, {}]}]}]}
    with pytest.raises(OtlpPayloadError, match="exceeds 1"):
        parse_otlp_json(payload, "127.0.0.1", max_records=1)
