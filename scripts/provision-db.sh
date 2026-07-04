#!/usr/bin/env bash
# provision-db.sh — create Ringdown's role + database + pgvector, apply schema.
#
# Run ON the database box as a Postgres SUPERUSER (the `vector` extension and
# CREATE ROLE/DATABASE need superuser):
#
#     sudo -u postgres bash provision-db.sh
#
# Idempotent: re-running won't error on an existing role/db; schema.sql is all
# CREATE ... IF NOT EXISTS / CREATE OR REPLACE. Writes the generated DSN to
# ../.env (RINGDOWN_DB_DSN=...) for the collector/mcp to pick up.
set -euo pipefail

DB=${RINGDOWN_DB_NAME:-ringdown}
ROLE=${RINGDOWN_DB_ROLE:-ringdown}
HERE=$(cd "$(dirname "$0")" && pwd)
SCHEMA="$HERE/../ringdown/schema.sql"
ENV_OUT="$HERE/../.env"

if [ -f "$ENV_OUT" ] && grep -q '^RINGDOWN_DB_DSN=' "$ENV_OUT"; then
    echo "[*] .env already has RINGDOWN_DB_DSN — reusing existing password."
    PW=$(sed -nE 's#^RINGDOWN_DB_DSN=postgresql://[^:]+:([^@]+)@.*#\1#p' "$ENV_OUT" | head -1)
else
    PW=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-28)
fi

echo "[*] role: $ROLE   db: $DB"
psql -v ON_ERROR_STOP=1 -d postgres <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${ROLE}') THEN
        CREATE ROLE ${ROLE} LOGIN PASSWORD '${PW}';
    ELSE
        ALTER ROLE ${ROLE} WITH LOGIN PASSWORD '${PW}';
    END IF;
END
\$\$;
SQL

if ! psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB}'" -d postgres | grep -q 1; then
    psql -v ON_ERROR_STOP=1 -d postgres -c "CREATE DATABASE ${DB} OWNER ${ROLE};"
    echo "[*] created database ${DB}"
else
    echo "[*] database ${DB} already exists"
fi

# pgvector must be enabled by a superuser, in the target db.
psql -v ON_ERROR_STOP=1 -d "$DB" -c "CREATE EXTENSION IF NOT EXISTS vector;"

# Apply the schema as the owner role so all objects belong to ringdown.
PGPASSWORD="$PW" psql -v ON_ERROR_STOP=1 -h "${RINGDOWN_DB_HOST:-localhost}" -U "$ROLE" -d "$DB" -f "$SCHEMA"
echo "[*] schema applied"

HOST_PUBLIC=${RINGDOWN_DB_PUBLIC_HOST:-localhost}
DSN="postgresql://${ROLE}:${PW}@${HOST_PUBLIC}:5432/${DB}"
umask 077
if grep -q '^RINGDOWN_DB_DSN=' "$ENV_OUT" 2>/dev/null; then
    sed -i -E "s#^RINGDOWN_DB_DSN=.*#RINGDOWN_DB_DSN=${DSN}#" "$ENV_OUT"
else
    echo "RINGDOWN_DB_DSN=${DSN}" >> "$ENV_OUT"
fi
echo "[*] wrote RINGDOWN_DB_DSN to $ENV_OUT  (host=${HOST_PUBLIC})"
echo "[✓] done. Verify:  psql '${DSN}' -c '\\dt'"
