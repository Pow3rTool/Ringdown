"""Safe operational projection of structured log attributes.

OTLP attributes are retained in the event row for database forensics, but MCP,
WebUI, rules, and L2 summaries expose only this explicit non-secret allowlist.
"""
from __future__ import annotations

VISIBLE_ATTRIBUTE_KEYS = (
    "event", "requestId", "outcome", "app", "appId", "provider", "providerId",
    "requestedModel", "model", "modelId", "mode", "stream", "failureClass",
    "failureDetail", "queueMs", "elapsedMs", "persisted", "status",
    "priorStatus", "discoveredModels", "latencyMs", "error", "virtual",
    "aliasId", "availableCandidates", "candidateCount", "alarm", "chart",
    "value", "units", "netdata.alarm.name", "netdata.chart",
    "netdata.status", "netdata.old_status", "netdata.value", "netdata.units",
    "netdata.family", "netdata.class", "netdata.component", "netdata.recipient",
)


def visible_attributes(value, *, string_limit: int = 512) -> dict:
    """Return a bounded scalar-only projection suitable for operators/agents."""
    if not isinstance(value, dict):
        return {}
    result = {}
    for key in VISIBLE_ATTRIBUTE_KEYS:
        item = value.get(key)
        if isinstance(item, bool):
            result[key] = item
        elif isinstance(item, (int, float)):
            result[key] = item
        elif isinstance(item, str):
            result[key] = item[:string_limit]
    return result


def attribute_context(value, *, max_chars: int = 4096) -> str:
    """Format the safe projection for rule matching and fenced triage context."""
    return " ".join(
        f"{key}={item}"
        for key, item in visible_attributes(value).items()
    )[:max_chars]
