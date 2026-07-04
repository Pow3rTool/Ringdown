-- 2026-07-04  webui server-side sessions (OIDC refresh-token backing)
--
-- The admin WebUI used to carry identity in a self-contained signed cookie with
-- a hard 8h absolute expiry: at 8h the cookie died and the operator was bounced
-- through the full interactive Entra flow (the observed "had to re-auth to even
-- reconnect" symptom). To keep the operator signed in across a work session we
-- now hold an Entra refresh token and silently re-validate; a refresh token is
-- a long-lived, high-value credential, so it is NEVER placed in a cookie.
--
-- The cookie now carries only an opaque session id (sid). This table holds the
-- session: identity, the refresh token ENCRYPTED AT REST (AES-256-GCM, key from
-- RINGDOWN_SESSION_ENC_KEY — the DB never sees plaintext), and the timers. Every
-- silent refresh re-checks the Ringdown.Admin role (soft revocation: a de-roled
-- admin loses access at the next refresh) and rotates the stored refresh token.
--
-- Fail-closed: any refresh error, a revoked row, or passing absolute_exp all
-- resolve to "no session" -> redirect to the interactive login. absolute_exp is
-- OUR hard ceiling (RINGDOWN_SESSION_ABSOLUTE_CAP_DAYS, default 30) and is the
-- longest a session can live regardless of activity; Entra's own refresh-token
-- lifetime is a secondary cap that surfaces as a failed refresh.
--
-- Additive and idempotent (CREATE ... IF NOT EXISTS). No existing table touched.

CREATE TABLE IF NOT EXISTS webui_sessions (
    sid            text         PRIMARY KEY,             -- opaque, secrets.token_urlsafe; the cookie value
    oid            text,                                 -- Entra object id of the operator
    upn            text,                                 -- preferred_username
    name           text,                                 -- display name
    refresh_enc    bytea        NOT NULL,                -- AES-256-GCM ciphertext of the refresh token
    refresh_nonce  bytea        NOT NULL,                -- 12-byte GCM nonce for refresh_enc
    access_exp     timestamptz  NOT NULL,                -- when the current access token dies (drives refresh)
    absolute_exp   timestamptz  NOT NULL,                -- hard ceiling; session cannot outlive this
    last_seen      timestamptz  NOT NULL DEFAULT now(),  -- sliding activity marker
    revoked        boolean      NOT NULL DEFAULT false,  -- set on logout / failed refresh / lost role
    created_at     timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS webui_sessions_gc ON webui_sessions (absolute_exp) WHERE NOT revoked;

-- Fold session GC into the existing daily retention tick. Expired or revoked
-- sessions are deleted (sessions are not history; 30d cap keeps this tiny). The
-- rest of the function body is copied verbatim from schema.sql so a fresh
-- provision and a migrated DB converge on the same definition.
CREATE OR REPLACE FUNCTION ringdown_retention(keep_days int DEFAULT 90)
RETURNS TABLE(dropped_partition text) LANGUAGE plpgsql AS $$
DECLARE
    cutoff timestamptz := now() - make_interval(days => keep_days);
    r      record;
    hi     text;
BEGIN
    FOR r IN
        SELECT c.oid, c.relname, pg_get_expr(c.relpartbound, c.oid) AS bound
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'events'
    LOOP
        hi := substring(r.bound from $re$TO \('([^']+)'\)$re$);
        CONTINUE WHEN hi IS NULL;
        IF hi::timestamptz <= cutoff THEN
            EXECUTE format('DROP TABLE IF EXISTS %I', r.relname);
            dropped_partition := r.relname;
            RETURN NEXT;
        END IF;
    END LOOP;

    UPDATE sources SET active = false
     WHERE active AND last_seen < cutoff;

    DELETE FROM semantic_evals WHERE evaluated_at < cutoff;

    -- expired or revoked WebUI sessions (bounded by absolute_exp, not keep_days)
    DELETE FROM webui_sessions WHERE revoked OR absolute_exp < now();
END $$;
