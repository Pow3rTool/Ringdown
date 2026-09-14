#!/usr/bin/env python3
"""Send one Netdata health transition to Ringdown as OTLP/HTTP JSON."""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request


FIELDS = (
    "recipient", "host", "name", "chart", "status", "old_status", "value",
    "units", "classification", "context", "component", "type", "alarm_id",
    "event_id", "transition_id", "when", "value_string",
)
SEVERITY = {"CLEAR": 9, "WARNING": 13, "CRITICAL": 18}


def _string_value(value: object) -> dict:
    return {"stringValue": str(value)[:4096]}


def _attribute(key: str, value: object) -> dict:
    return {"key": key, "value": _string_value(value)}


def build_payload(arguments: list[str], *, now_ns: int | None = None) -> dict:
    values = dict(zip(FIELDS, arguments, strict=False))
    host = values.get("host") or "unknown-netdata-host"
    status = (values.get("status") or "UNKNOWN").upper()
    old_status = (values.get("old_status") or "UNKNOWN").upper()
    timestamp_ns = now_ns if now_ns is not None else time.time_ns()
    try:
        timestamp_ns = int(float(values.get("when", "")) * 1_000_000_000)
    except (TypeError, ValueError, OverflowError):
        pass

    display_value = values.get("value_string") or " ".join(
        part for part in (values.get("value", ""), values.get("units", "")) if part
    )
    body = (
        f"Netdata alarm {values.get('name') or 'unknown'} {old_status} -> {status} "
        f"on {values.get('chart') or 'unknown'}"
    )
    if display_value:
        body += f": {display_value}"

    attributes = [_attribute("event", "netdata.alarm")]
    attribute_fields = {
        "netdata.recipient": "recipient",
        "netdata.alarm.name": "name",
        "netdata.chart": "chart",
        "netdata.status": "status",
        "netdata.old_status": "old_status",
        "netdata.value": "value",
        "netdata.units": "units",
        "netdata.class": "classification",
        "netdata.context": "context",
        "netdata.component": "component",
        "netdata.type": "type",
        "netdata.alarm.id": "alarm_id",
        "netdata.event.id": "event_id",
        "netdata.transition.id": "transition_id",
    }
    for otel_key, field in attribute_fields.items():
        value = values.get(field)
        if value:
            attributes.append(_attribute(otel_key, value))

    record = {
        "timeUnixNano": str(timestamp_ns),
        "observedTimeUnixNano": str(time.time_ns()),
        "severityNumber": SEVERITY.get(status, 9),
        "severityText": status,
        "body": _string_value(body),
        "attributes": attributes,
    }
    return {
        "resourceLogs": [{
            "resource": {"attributes": [
                _attribute("service.name", "netdata"),
                _attribute("service.instance.id", host),
                _attribute("host.name", host),
            ]},
            "scopeLogs": [{
                "scope": {"name": "netdata-health"},
                "logRecords": [record],
            }],
        }],
    }


def main() -> int:
    endpoint = os.environ.get("RINGDOWN_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        print("RINGDOWN_OTLP_ENDPOINT is required", file=sys.stderr)
        return 2
    payload = json.dumps(build_payload(sys.argv[1:]), separators=(",", ":")).encode()
    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            response.read(4096)
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"HTTP {response.status}")
    except Exception as exc:
        print(f"Ringdown OTLP delivery failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
