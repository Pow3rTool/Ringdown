"""Ringdown — ingest logs, decide what matters, ring the right responder.

Successor to the Ringdown prototype. Three processes over one Postgres (no direct IPC):
  * ringdown.collector — the hot path (ingress filter + store + alert/dispatch).
  * ringdown.mcp_server — the Entra-gated control plane (CRUD + query).
  * ringdown.webui — the admin live view + ingress-filter control plane.
"""

__version__ = "0.1.0"
