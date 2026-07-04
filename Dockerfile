# Ringdown — single image, three roles (collector / mcp_server / webui),
# selected by the container command (see each Quadlet's Exec=).
#
# Pure-Python, PyPI wheels only (psycopg[binary,pool], uvicorn, mcp/FastMCP,
# pyjwt[crypto]) — no apt build deps, no compiler.
#
# Config + secrets are NEVER baked. At runtime the deploy mounts (read-only):
#   /app/.env                  — the config the app's own load_env() parses
#   /opt/ringdown/oidc/        — webui's private_key_jwt cert+key (default paths)
# and (read-write):
#   /var/log/ringdown/         — the collector/mcp append-only audit log
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

WORKDIR /app

# Pinned closure first (cached layer; also the SCA manifest the repo keeps).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App as source on PYTHONPATH — NOT pip-installed, so config.load_env() resolves
# `<pkg>/../.env` to /app/.env (matches the deploy box's WorkingDirectory layout).
COPY ringdown/ ./ringdown/
COPY pyproject.toml README.md LICENSE ./

# Match the deploy box's ringdown acct (997:987) so the mounted .env/oidc (0600)
# and the audit dir (owned ringdown:ringdown) are readable/writable as-is.
RUN groupadd --system --gid 987 ringdown \
 && useradd  --system --uid 997 --gid 987 --home-dir /app --shell /usr/sbin/nologin ringdown
USER 997:987

# Default role; every Quadlet overrides this via Exec=.
CMD ["python", "-m", "ringdown.mcp_server"]
