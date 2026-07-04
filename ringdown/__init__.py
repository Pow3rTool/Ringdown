"""Ringdown — ingest logs, decide what matters, ring the right responder.

Successor to the Ringdown prototype. Two processes over one Postgres (no direct IPC):
  * ringdown.collector — the hot path (ingest + L1 match + L2 judge + dispatch).
  * ringdown.mcp_server — the Entra-gated control plane (CRUD + query).
"""

__version__ = "0.1.0"
