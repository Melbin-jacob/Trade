-- =============================================================================
-- Trade-Lane Sentinel - 0001: tenant provisioning + append-only audit ledger
--
-- Isolation model (defence in depth):
--   1. one schema per tenant (t_<tenant>) owned by the migration role
--   2. one NOLOGIN role per tenant (tenant_<tenant>) with USAGE on ONLY its schema;
--      application connections SET ROLE to it after authenticating the request
--   3. row-level security keyed on current_setting('app.tenant_id') as a second lock
--
-- Ledger guarantees enforced by the database itself (not just the app):
--   * INSERT only - UPDATE / DELETE / TRUNCATE raise, even for the table owner
--   * gap-free sequence and prev_hash linkage checked under a head-row lock
--   * gap-free per-aggregate versions (optimistic concurrency)
-- Hash and Ed25519 signature verification is done by the application's
-- verify_chain() job, using public keys from the KMS.
--
-- Encryption: TLS 1.3 is enforced on the server (ssl_min_protocol_version);
-- storage is encrypted with a customer-managed AES-256 key (RDS/Cloud SQL/Azure
-- CMK); document blobs are additionally envelope-encrypted per tenant.
-- =============================================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS sentinel_admin;
REVOKE ALL ON SCHEMA sentinel_admin FROM PUBLIC;

CREATE TABLE IF NOT EXISTS sentinel_admin.tenants (
    tenant_id    text PRIMARY KEY CHECK (tenant_id ~ '^[a-z][a-z0-9_]{2,40}$'),
    schema_name  text NOT NULL UNIQUE,
    db_role      text NOT NULL UNIQUE,
    kms_key_ref  text NOT NULL,           -- per-tenant CMK used for blob envelope encryption
    data_region  text NOT NULL,           -- residency pin, e.g. 'ca-central-1'
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Trigger functions (shared by every tenant schema)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION sentinel_admin.forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ledger is append-only: % on %.% is forbidden',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE OR REPLACE FUNCTION sentinel_admin.link_chain() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    head_seq  bigint;
    head_hash text;
    agg_ver   integer;
BEGIN
    -- Serialises all writers of this tenant's chain.
    EXECUTE format('SELECT sequence, entry_hash FROM %I.chain_head FOR UPDATE', TG_TABLE_SCHEMA)
        INTO head_seq, head_hash;

    IF NEW.sequence <> head_seq + 1 OR NEW.prev_hash <> head_hash THEN
        -- 40001 = another writer appended first; safe to rebuild and retry
        RAISE EXCEPTION 'chain head moved (head=%, got=%)', head_seq, NEW.sequence
            USING ERRCODE = 'serialization_failure';
    END IF;

    EXECUTE format('SELECT coalesce(max(aggregate_version), 0) FROM %I.ledger_entries WHERE aggregate_id = $1',
                   TG_TABLE_SCHEMA)
        INTO agg_ver USING NEW.aggregate_id;
    IF NEW.aggregate_version <> agg_ver + 1 THEN
        -- SNT02 = optimistic-concurrency conflict (caller must reload and re-decide)
        RAISE EXCEPTION 'aggregate % is at v%, got v%', NEW.aggregate_id, agg_ver, NEW.aggregate_version
            USING ERRCODE = 'SNT02';
    END IF;

    EXECUTE format('UPDATE %I.chain_head SET sequence = $1, entry_hash = $2', TG_TABLE_SCHEMA)
        USING NEW.sequence, NEW.entry_hash;
    RETURN NEW;
END $$;

-- ---------------------------------------------------------------------------
-- Tenant provisioning
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION sentinel_admin.provision_tenant(
    p_tenant text, p_kms_key_ref text, p_region text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, sentinel_admin AS $$
DECLARE
    s text := 't_' || p_tenant;
    r text := 'tenant_' || p_tenant;
BEGIN
    IF p_tenant !~ '^[a-z][a-z0-9_]{2,40}$' THEN
        RAISE EXCEPTION 'invalid tenant id %', p_tenant;
    END IF;

    INSERT INTO sentinel_admin.tenants (tenant_id, schema_name, db_role, kms_key_ref, data_region)
    VALUES (p_tenant, s, r, p_kms_key_ref, p_region);

    EXECUTE format('CREATE SCHEMA %I', s);
    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', s);
    EXECUTE format('CREATE ROLE %I NOLOGIN', r);

    EXECUTE format($ddl$
        CREATE TABLE %1$I.ledger_entries (
            tenant_id          text        NOT NULL DEFAULT %2$L CHECK (tenant_id = %2$L),
            sequence           bigint      PRIMARY KEY CHECK (sequence > 0),
            entry_id           uuid        NOT NULL UNIQUE,
            recorded_at        timestamptz NOT NULL,
            aggregate_type     text        NOT NULL,
            aggregate_id       text        NOT NULL,
            aggregate_version  integer     NOT NULL CHECK (aggregate_version > 0),
            event_type         text        NOT NULL,
            actor              jsonb       NOT NULL,
            payload            jsonb       NOT NULL,
            prev_hash          char(64)    NOT NULL UNIQUE,
            entry_hash         char(64)    NOT NULL UNIQUE,
            key_id             text        NOT NULL,
            signature          text        NOT NULL,
            UNIQUE (aggregate_id, aggregate_version)
        )$ddl$, s, p_tenant);
    EXECUTE format('CREATE INDEX ON %I.ledger_entries (aggregate_id, aggregate_version)', s);

    EXECUTE format($ddl$
        CREATE TABLE %I.chain_head (
            singleton   boolean  PRIMARY KEY DEFAULT true CHECK (singleton),
            sequence    bigint   NOT NULL,
            entry_hash  char(64) NOT NULL
        )$ddl$, s);
    EXECUTE format('INSERT INTO %I.chain_head (sequence, entry_hash) VALUES (0, repeat(''0'', 64))', s);

    -- Append-only enforcement
    EXECUTE format('CREATE TRIGGER link_chain BEFORE INSERT ON %I.ledger_entries
                    FOR EACH ROW EXECUTE FUNCTION sentinel_admin.link_chain()', s);
    EXECUTE format('CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON %I.ledger_entries
                    FOR EACH ROW EXECUTE FUNCTION sentinel_admin.forbid_mutation()', s);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON %I.ledger_entries
                    FOR EACH STATEMENT EXECUTE FUNCTION sentinel_admin.forbid_mutation()', s);

    -- Row-level security (second lock)
    EXECUTE format('ALTER TABLE %I.ledger_entries ENABLE ROW LEVEL SECURITY', s);
    EXECUTE format('ALTER TABLE %I.ledger_entries FORCE ROW LEVEL SECURITY', s);
    EXECUTE format($p$CREATE POLICY tenant_rows ON %I.ledger_entries
                     USING (tenant_id = current_setting('app.tenant_id', true))
                     WITH CHECK (tenant_id = current_setting('app.tenant_id', true))$p$, s);

    -- Least privilege: the tenant role may read and append, nothing else.
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', s, r);
    EXECUTE format('GRANT SELECT, INSERT ON %I.ledger_entries TO %I', s, r);
    EXECUTE format('GRANT SELECT ON %I.chain_head TO %I', s, r);
END $$;

REVOKE ALL ON FUNCTION sentinel_admin.provision_tenant(text, text, text) FROM PUBLIC;

COMMIT;
