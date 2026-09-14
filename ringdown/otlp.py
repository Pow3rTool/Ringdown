"""Bounded OTLP/HTTP JSON ingress for Ringdown's existing event pipeline."""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


class OtlpPayloadError(ValueError):
    """The OTLP JSON envelope is malformed or exceeds a structural bound."""


def allowed_networks(cidrs: Iterable[str]) -> tuple[ipaddress._BaseNetwork, ...]:
    return tuple(ipaddress.ip_network(value, strict=False) for value in cidrs)


def peer_allowed(peer: str | None, networks: Iterable[ipaddress._BaseNetwork]) -> bool:
    """Authorize only the socket peer; forwarding headers are deliberately ignored."""
    if not peer:
        return False
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address.version == network.version and address in network for network in networks)


def _any_value(value: Any, depth: int = 0) -> Any:
    if not isinstance(value, dict) or depth > 8:
        return None
    if "stringValue" in value:
        return str(value["stringValue"])
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "intValue" in value:
        try:
            number = int(value["intValue"])
            return number if -(2**63) <= number < 2**63 else str(number)
        except (TypeError, ValueError):
            return str(value["intValue"])
    if "doubleValue" in value:
        try:
            return float(value["doubleValue"])
        except (TypeError, ValueError):
            return None
    if "bytesValue" in value:
        return str(value["bytesValue"])
    if "arrayValue" in value:
        values = value["arrayValue"].get("values", []) if isinstance(value["arrayValue"], dict) else []
        return [_any_value(item, depth + 1) for item in values[:256]]
    if "kvlistValue" in value:
        pairs = value["kvlistValue"].get("values", []) if isinstance(value["kvlistValue"], dict) else []
        return _attributes(pairs, depth + 1)
    return None


def _attributes(values: Any, depth: int = 0) -> dict[str, Any]:
    if not isinstance(values, list):
        return {}
    result: dict[str, Any] = {}
    for item in values[:256]:
        if isinstance(item, dict) and "key" in item:
            result[str(item["key"])[:512]] = _any_value(item.get("value"), depth)
    return result


def _timestamp(record: dict[str, Any]) -> datetime:
    raw = record.get("timeUnixNano") or record.get("observedTimeUnixNano")
    try:
        nanoseconds = int(raw)
        if nanoseconds > 0:
            return datetime.fromtimestamp(nanoseconds / 1_000_000_000, tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        pass
    return datetime.now(timezone.utc)


def _text(value: Any, limit: int) -> str | None:
    return None if value is None else str(value)[:limit]


def parse_otlp_json(payload: Any, peer: str, max_records: int = 5000) -> list[dict[str, Any]]:
    """Normalize one ExportLogsServiceRequest encoded with OTLP/HTTP JSON."""
    if not isinstance(payload, dict):
        raise OtlpPayloadError("top-level OTLP payload must be an object")
    resource_logs = payload.get("resourceLogs", [])
    if not isinstance(resource_logs, list):
        raise OtlpPayloadError("resourceLogs must be an array")

    events: list[dict[str, Any]] = []
    for resource_group in resource_logs:
        if not isinstance(resource_group, dict):
            raise OtlpPayloadError("resourceLogs entries must be objects")
        resource = resource_group.get("resource", {})
        resource_attrs = _attributes(resource.get("attributes", []) if isinstance(resource, dict) else [])
        scope_logs = resource_group.get("scopeLogs", [])
        if not isinstance(scope_logs, list):
            raise OtlpPayloadError("scopeLogs must be an array")
        for scope_group in scope_logs:
            if not isinstance(scope_group, dict):
                raise OtlpPayloadError("scopeLogs entries must be objects")
            scope = scope_group.get("scope", {})
            scope_attrs: dict[str, Any] = {}
            if isinstance(scope, dict):
                for key in ("name", "version"):
                    if scope.get(key) is not None:
                        scope_attrs[key] = _text(scope[key], 512)
                scope_attrs.update(_attributes(scope.get("attributes", [])))
            records = scope_group.get("logRecords", [])
            if not isinstance(records, list):
                raise OtlpPayloadError("logRecords must be an array")
            for record in records:
                if len(events) >= max_records:
                    raise OtlpPayloadError(f"request exceeds {max_records} log records")
                if not isinstance(record, dict):
                    raise OtlpPayloadError("logRecords entries must be objects")
                record_attrs = _attributes(record.get("attributes", []))
                body_value = _any_value(record.get("body", {}))
                body = body_value if isinstance(body_value, str) else json.dumps(
                    body_value, ensure_ascii=False, separators=(",", ":"))
                try:
                    severity = int(record.get("severityNumber", 0))
                    severity = severity if 1 <= severity <= 24 else None
                except (TypeError, ValueError):
                    severity = None
                attributes = dict(record_attrs)
                attributes.update({
                    "resource": resource_attrs,
                    "scope": scope_attrs,
                    "ringdown.ingress": "otlp/http-json",
                    "ringdown.peer.ip": peer,
                })
                for key in ("traceId", "spanId", "flags"):
                    if record.get(key) is not None:
                        attributes[f"otel.{key}"] = record[key]
                events.append({
                    "ts": _timestamp(record),
                    "source": _text(resource_attrs.get("host.name"), 255)
                              or _text(resource_attrs.get("service.instance.id"), 255) or peer,
                    "facility": _text(record_attrs.get("log.syslog.facility.name"), 64),
                    "severity": severity,
                    "severity_text": _text(record.get("severityText"), 64),
                    "program": _text(resource_attrs.get("service.name"), 255)
                               or _text(scope_attrs.get("name"), 255) or "otlp",
                    "body": body[:64_000],
                    "attributes": attributes,
                    "raw": json.dumps(record, ensure_ascii=False, separators=(",", ":"))[:64_000],
                })
    return events


def create_otlp_app(queue, cidrs: Iterable[str], max_body_bytes: int, max_records: int) -> Starlette:
    networks = allowed_networks(cidrs)

    async def export_logs(request: Request):
        peer = request.client.host if request.client else None
        if not peer_allowed(peer, networks):
            return JSONResponse({"error": "source network is not trusted"}, status_code=403)
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return JSONResponse({"error": "only OTLP/HTTP JSON is enabled"}, status_code=415)
        try:
            declared = int(request.headers.get("content-length", "0") or 0)
        except ValueError:
            return JSONResponse({"error": "invalid content-length"}, status_code=400)
        if declared > max_body_bytes:
            return JSONResponse({"error": "OTLP request body is too large"}, status_code=413)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > max_body_bytes:
                return JSONResponse(
                    {"error": "OTLP request body is too large"},
                    status_code=413,
                )
        try:
            events = parse_otlp_json(json.loads(body), peer or "unknown", max_records)
        except (json.JSONDecodeError, UnicodeDecodeError, OtlpPayloadError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        available = queue.maxsize - queue.qsize() if queue.maxsize else len(events)
        if len(events) > available:
            return JSONResponse(
                {"error": "collector queue is full; retry later"},
                status_code=503,
                headers={"Retry-After": "1"},
            )
        for event in events:
            queue.put_nowait(event)
        return JSONResponse({})

    async def health(request: Request):
        peer = request.client.host if request.client else None
        if not peer_allowed(peer, networks):
            return JSONResponse({"error": "source network is not trusted"}, status_code=403)
        return JSONResponse({"status": "ok", "queueDepth": queue.qsize()})

    return Starlette(routes=[
        Route("/v1/logs", export_logs, methods=["POST"]),
        Route("/healthz", health, methods=["GET"]),
    ])
