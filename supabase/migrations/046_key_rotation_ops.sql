-- ============================================================
-- 046_key_rotation_ops.sql — confidential key-rotation contract
-- ============================================================
-- Expand-only. Production rollback is disable/revoke/fix-forward. This
-- migration intentionally contains no destructive DOWN section.

CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_extension AS extension
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = extension.extnamespace
    WHERE extension.extname = 'pgcrypto'
      AND namespace.nspname <> 'extensions'
  ) THEN
    ALTER EXTENSION pgcrypto SET SCHEMA extensions;
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'key_rotation_executor'
  ) THEN
    CREATE ROLE key_rotation_executor NOLOGIN BYPASSRLS;
  END IF;
END
$$;

GRANT USAGE, CREATE ON SCHEMA public TO key_rotation_executor;
GRANT USAGE ON SCHEMA auth, extensions TO key_rotation_executor;
GRANT EXECUTE ON FUNCTION auth.role(), auth.uid() TO key_rotation_executor;
GRANT EXECUTE ON FUNCTION extensions.digest(BYTEA, TEXT)
  TO key_rotation_executor;

-- Authoritative allow-list used by item and manifest constraints. Data access
-- code may map these paths to columns, but it must not define another policy.
CREATE FUNCTION public.rotation_allowed_paths(p_table_name TEXT)
RETURNS TEXT[]
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT CASE p_table_name
    WHEN 'whatsapp_config' THEN ARRAY[
      'access_token', 'verify_token', 'provider_config.apiKey',
      'provider_config.secret'
    ]::TEXT[]
    WHEN 'salesforce_config' THEN ARRAY[
      'client_id', 'client_secret', 'username', 'password',
      'security_token', 'webhook_secret'
    ]::TEXT[]
    WHEN 'ai_configs' THEN ARRAY['api_key', 'embeddings_api_key']::TEXT[]
    WHEN 'webhook_endpoints' THEN ARRAY['secret']::TEXT[]
    ELSE ARRAY[]::TEXT[]
  END;
$$;

ALTER FUNCTION public.rotation_allowed_paths(TEXT)
  OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION public.rotation_allowed_paths(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;

-- SECURITY DEFINER functions below use only pg_catalog and public. Public is
-- trusted because unprivileged roles cannot create schema objects there.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM anon, authenticated, service_role;

-- Encrypted-row metadata. Fingerprints are random opaque concurrency tokens;
-- they are never derived from plaintext or ciphertext.
-- Migration 045 contains its historical DOWN section in the same file, so a
-- fresh migration replay drops this drift-repair column after adding it. 046
-- has not shipped yet and must repair the final state before compiling triggers.
ALTER TABLE salesforce_config
  ADD COLUMN IF NOT EXISTS webhook_secret TEXT;

ALTER TABLE whatsapp_config
  ADD COLUMN secret_version BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN secret_fingerprint UUID NOT NULL DEFAULT gen_random_uuid();

ALTER TABLE salesforce_config
  ADD COLUMN secret_version BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN secret_fingerprint UUID NOT NULL DEFAULT gen_random_uuid();

ALTER TABLE ai_configs
  ADD COLUMN secret_version BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN secret_fingerprint UUID NOT NULL DEFAULT gen_random_uuid();

ALTER TABLE webhook_endpoints
  ADD COLUMN secret_version BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN secret_fingerprint UUID NOT NULL DEFAULT gen_random_uuid();

-- Account-scoped advisory locks are the database write barrier shared by
-- ordinary application secret writes and rotation lifecycle gates. The hash is
-- namespaced to this contract; collisions are safe and only reduce concurrency.
-- Multi-account acquisition (encrypted-row transfers and the DELETE barrier)
-- sorts the accounts first so any two operations touching the same pair lock
-- them in the same order and can never deadlock each other.
CREATE FUNCTION public.lock_key_rotation_accounts(p_account_ids UUID[])
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '5s'
AS $$
DECLARE
  v_account_id UUID;
BEGIN
  IF p_account_ids IS NULL OR cardinality(p_account_ids) = 0 OR
     NOT EXISTS (
       SELECT 1 FROM unnest(p_account_ids) AS ids(account_id)
       WHERE ids.account_id IS NOT NULL
     ) THEN
    RAISE EXCEPTION 'key rotation account is required' USING ERRCODE = '22023';
  END IF;
  FOR v_account_id IN
    SELECT DISTINCT ids.account_id
    FROM unnest(p_account_ids) AS ids(account_id)
    WHERE ids.account_id IS NOT NULL
    ORDER BY ids.account_id
  LOOP
    PERFORM pg_advisory_xact_lock(
      hashtextextended('key_rotation:' || v_account_id::TEXT, 0)
    );
  END LOOP;
END;
$$;

CREATE FUNCTION public.lock_key_rotation_account(p_account_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '5s'
AS $$
BEGIN
  PERFORM public.lock_key_rotation_accounts(ARRAY[p_account_id]);
END;
$$;

ALTER FUNCTION public.lock_key_rotation_accounts(UUID[])
  OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION public.lock_key_rotation_accounts(UUID[])
  FROM PUBLIC, anon, authenticated, service_role;
ALTER FUNCTION public.lock_key_rotation_account(UUID)
  OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION public.lock_key_rotation_account(UUID)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION public.bump_key_rotation_secret_metadata()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  encrypted_value_changed BOOLEAN;
BEGIN
  IF TG_OP = 'INSERT' THEN
    encrypted_value_changed := CASE TG_TABLE_NAME
      WHEN 'whatsapp_config' THEN
        NEW.access_token IS NOT NULL OR NEW.verify_token IS NOT NULL OR
        NEW.provider_config ->> 'apiKey' IS NOT NULL OR
        NEW.provider_config ->> 'secret' IS NOT NULL
      WHEN 'salesforce_config' THEN
        NEW.client_id IS NOT NULL OR NEW.client_secret IS NOT NULL OR
        NEW.username IS NOT NULL OR NEW.password IS NOT NULL OR
        NEW.security_token IS NOT NULL OR NEW.webhook_secret IS NOT NULL
      WHEN 'ai_configs' THEN
        NEW.api_key IS NOT NULL OR NEW.embeddings_api_key IS NOT NULL
      WHEN 'webhook_endpoints' THEN NEW.secret IS NOT NULL
      ELSE FALSE
    END;
    IF encrypted_value_changed THEN
      PERFORM public.lock_key_rotation_account(NEW.account_id);
    END IF;
    RETURN NEW;
  END IF;

  -- Removing an encrypted row must not race a rotation or finalization of the
  -- account it belongs to, so DELETE participates in the same write barrier.
  IF TG_OP = 'DELETE' THEN
    encrypted_value_changed := CASE TG_TABLE_NAME
      WHEN 'whatsapp_config' THEN
        OLD.access_token IS NOT NULL OR OLD.verify_token IS NOT NULL OR
        OLD.provider_config ->> 'apiKey' IS NOT NULL OR
        OLD.provider_config ->> 'secret' IS NOT NULL
      WHEN 'salesforce_config' THEN
        OLD.client_id IS NOT NULL OR OLD.client_secret IS NOT NULL OR
        OLD.username IS NOT NULL OR OLD.password IS NOT NULL OR
        OLD.security_token IS NOT NULL OR OLD.webhook_secret IS NOT NULL
      WHEN 'ai_configs' THEN
        OLD.api_key IS NOT NULL OR OLD.embeddings_api_key IS NOT NULL
      WHEN 'webhook_endpoints' THEN OLD.secret IS NOT NULL
      ELSE FALSE
    END;
    IF encrypted_value_changed THEN
      PERFORM public.lock_key_rotation_account(OLD.account_id);
    END IF;
    RETURN OLD;
  END IF;

  -- An encrypted row may move between accounts. Both inventories must be under
  -- the barrier, acquired in deterministic order, so a transfer can never race
  -- a rotation or finalization of either account.
  IF NEW.account_id IS DISTINCT FROM OLD.account_id THEN
    PERFORM public.lock_key_rotation_accounts(
      ARRAY[OLD.account_id, NEW.account_id]
    );
  END IF;

  encrypted_value_changed := CASE TG_TABLE_NAME
    WHEN 'whatsapp_config' THEN
      OLD.access_token IS DISTINCT FROM NEW.access_token OR
      OLD.verify_token IS DISTINCT FROM NEW.verify_token OR
      OLD.provider_config ->> 'apiKey' IS DISTINCT FROM NEW.provider_config ->> 'apiKey' OR
      OLD.provider_config ->> 'secret' IS DISTINCT FROM NEW.provider_config ->> 'secret'
    WHEN 'salesforce_config' THEN
      OLD.client_id IS DISTINCT FROM NEW.client_id OR
      OLD.client_secret IS DISTINCT FROM NEW.client_secret OR
      OLD.username IS DISTINCT FROM NEW.username OR
      OLD.password IS DISTINCT FROM NEW.password OR
      OLD.security_token IS DISTINCT FROM NEW.security_token OR
      OLD.webhook_secret IS DISTINCT FROM NEW.webhook_secret
    WHEN 'ai_configs' THEN
      OLD.api_key IS DISTINCT FROM NEW.api_key OR
      OLD.embeddings_api_key IS DISTINCT FROM NEW.embeddings_api_key
    WHEN 'webhook_endpoints' THEN
      OLD.secret IS DISTINCT FROM NEW.secret
    ELSE FALSE
  END;

  IF encrypted_value_changed THEN
    PERFORM public.lock_key_rotation_account(NEW.account_id);
    NEW.secret_version := OLD.secret_version + 1;
    NEW.secret_fingerprint := gen_random_uuid();
  ELSE
    NEW.secret_version := OLD.secret_version;
    NEW.secret_fingerprint := OLD.secret_fingerprint;
  END IF;
  RETURN NEW;
END;
$$;

ALTER FUNCTION public.bump_key_rotation_secret_metadata() OWNER TO key_rotation_executor;

CREATE TRIGGER whatsapp_config_secret_metadata
  BEFORE INSERT OR UPDATE OR DELETE ON whatsapp_config
  FOR EACH ROW EXECUTE FUNCTION public.bump_key_rotation_secret_metadata();
CREATE TRIGGER salesforce_config_secret_metadata
  BEFORE INSERT OR UPDATE OR DELETE ON salesforce_config
  FOR EACH ROW EXECUTE FUNCTION public.bump_key_rotation_secret_metadata();
CREATE TRIGGER ai_configs_secret_metadata
  BEFORE INSERT OR UPDATE OR DELETE ON ai_configs
  FOR EACH ROW EXECUTE FUNCTION public.bump_key_rotation_secret_metadata();
CREATE TRIGGER webhook_endpoints_secret_metadata
  BEFORE INSERT OR UPDATE OR DELETE ON webhook_endpoints
  FOR EACH ROW EXECUTE FUNCTION public.bump_key_rotation_secret_metadata();

-- One closed, non-dynamic inventory implementation is reused by snapshot and
-- gate reconciliation so the 13-path policy cannot drift between phases.
CREATE FUNCTION public.key_rotation_inventory(p_account_id UUID)
RETURNS TABLE (
  table_name TEXT,
  row_id UUID,
  account_id UUID,
  target_paths TEXT[],
  secret_version BIGINT,
  secret_fingerprint UUID
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT *
  FROM (
    SELECT
      'whatsapp_config'::TEXT,
      config.id,
      config.account_id,
      array_remove(ARRAY[
        CASE WHEN config.access_token IS NOT NULL THEN 'access_token' END,
        CASE WHEN config.verify_token IS NOT NULL THEN 'verify_token' END,
        CASE WHEN config.provider_config ->> 'apiKey' IS NOT NULL
          THEN 'provider_config.apiKey' END,
        CASE WHEN config.provider_config ->> 'secret' IS NOT NULL
          THEN 'provider_config.secret' END
      ]::TEXT[], NULL),
      config.secret_version,
      config.secret_fingerprint
    FROM public.whatsapp_config AS config
    WHERE config.account_id = p_account_id

    UNION ALL

    SELECT
      'salesforce_config'::TEXT,
      config.id,
      config.account_id,
      array_remove(ARRAY[
        CASE WHEN config.client_id IS NOT NULL THEN 'client_id' END,
        CASE WHEN config.client_secret IS NOT NULL THEN 'client_secret' END,
        CASE WHEN config.username IS NOT NULL THEN 'username' END,
        CASE WHEN config.password IS NOT NULL THEN 'password' END,
        CASE WHEN config.security_token IS NOT NULL THEN 'security_token' END,
        CASE WHEN config.webhook_secret IS NOT NULL THEN 'webhook_secret' END
      ]::TEXT[], NULL),
      config.secret_version,
      config.secret_fingerprint
    FROM public.salesforce_config AS config
    WHERE config.account_id = p_account_id

    UNION ALL

    SELECT
      'ai_configs'::TEXT,
      config.id,
      config.account_id,
      array_remove(ARRAY[
        CASE WHEN config.api_key IS NOT NULL THEN 'api_key' END,
        CASE WHEN config.embeddings_api_key IS NOT NULL
          THEN 'embeddings_api_key' END
      ]::TEXT[], NULL),
      config.secret_version,
      config.secret_fingerprint
    FROM public.ai_configs AS config
    WHERE config.account_id = p_account_id

    UNION ALL

    SELECT
      'webhook_endpoints'::TEXT,
      endpoint.id,
      endpoint.account_id,
      ARRAY['secret']::TEXT[],
      endpoint.secret_version,
      endpoint.secret_fingerprint
    FROM public.webhook_endpoints AS endpoint
    WHERE endpoint.account_id = p_account_id AND endpoint.secret IS NOT NULL
  ) AS inventory
  WHERE cardinality(inventory.target_paths) > 0;
$$;

ALTER FUNCTION public.key_rotation_inventory(UUID)
  OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION public.key_rotation_inventory(UUID)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE TABLE rotation_runtime_control (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  operations_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  disabled_reason TEXT NOT NULL DEFAULT 'not_enabled'
    CONSTRAINT rotation_runtime_reason_check CHECK (
      disabled_reason IN (
        'not_enabled', 'enabled', 'operator_disabled', 'incident_response',
        'maintenance', 'fix_forward'
      )
    ),
  updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO rotation_runtime_control (singleton)
VALUES (TRUE);

CREATE TABLE rotation_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  mode TEXT NOT NULL
    CONSTRAINT rotation_run_mode_check CHECK (mode IN ('dry_run', 'apply', 'final_audit')),
  status TEXT NOT NULL DEFAULT 'planned'
    CONSTRAINT rotation_run_status_check CHECK (
      status IN (
        'planned', 'awaiting_approval', 'approved', 'running', 'completed',
        'blocked', 'retired'
      )
    ),
  reason_code TEXT NOT NULL DEFAULT 'created'
    CONSTRAINT rotation_reason_code_check CHECK (
      reason_code IN (
        'created', 'started', 'manifest_pending', 'manifest_reimported',
        'approval_required', 'digest_mismatch', 'role_collision',
        'unknown_ownership', 'invalid_payload', 'conflict', 'missing',
        'completed', 'count_mismatch', 'gate_failed', 'retention_active',
        'inventory_changed', 'zero_inventory',
        'already_purged', 'operator_disabled',
        'incident_response', 'maintenance', 'fix_forward', 'none'
      )
    ),
  current_key_fingerprint UUID NOT NULL,
  previous_key_fingerprint UUID,
  operator_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  expected_items BIGINT NOT NULL DEFAULT 0 CHECK (expected_items >= 0),
  visited_items BIGINT NOT NULL DEFAULT 0 CHECK (visited_items >= 0),
  terminal_items BIGINT NOT NULL DEFAULT 0 CHECK (terminal_items >= 0),
  applied_values BIGINT NOT NULL DEFAULT 0 CHECK (applied_values >= 0),
  current_values BIGINT NOT NULL DEFAULT 0 CHECK (current_values >= 0),
  previous_values BIGINT NOT NULL DEFAULT 0 CHECK (previous_values >= 0),
  unknown_values BIGINT NOT NULL DEFAULT 0 CHECK (unknown_values >= 0),
  failed_values BIGINT NOT NULL DEFAULT 0 CHECK (failed_values >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  previous_key_retired_at TIMESTAMPTZ,
  purge_after TIMESTAMPTZ,
  CONSTRAINT rotation_run_retention_check CHECK (
    (previous_key_retired_at IS NULL AND purge_after IS NULL) OR
    (previous_key_retired_at IS NOT NULL AND
      purge_after = previous_key_retired_at + INTERVAL '90 days')
  ),
  CONSTRAINT rotation_run_counts_check CHECK (
    visited_items <= expected_items AND terminal_items <= visited_items
  ),
  UNIQUE (id, account_id)
);

CREATE TABLE rotation_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  table_name TEXT NOT NULL
    CONSTRAINT rotation_item_table_check CHECK (
      table_name IN ('whatsapp_config', 'salesforce_config', 'ai_configs', 'webhook_endpoints')
    ),
  row_id UUID NOT NULL,
  target_paths TEXT[] NOT NULL CHECK (cardinality(target_paths) > 0),
  expected_version BIGINT NOT NULL CHECK (expected_version >= 0),
  expected_fingerprint UUID NOT NULL,
  status TEXT NOT NULL DEFAULT 'planned'
    CONSTRAINT rotation_item_status_check CHECK (
      status IN (
        'planned', 'validated', 'approved', 'applied', 'conflict',
        'missing', 'blocked'
      )
    ),
  reason_code TEXT NOT NULL DEFAULT 'none'
    CONSTRAINT rotation_item_reason_check CHECK (
      reason_code IN (
        'none', 'applied', 'already_applied', 'version_conflict',
        'row_missing', 'invalid_payload', 'approval_required',
        'unknown_ownership', 'digest_mismatch', 'role_collision',
        'operations_disabled', 'payload_mismatch', 'mode_read_only'
      )
    ),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  applied_version BIGINT CHECK (applied_version >= 0),
  applied_fingerprint UUID,
  replacement_payload_digest BYTEA
    CHECK (replacement_payload_digest IS NULL OR
      octet_length(replacement_payload_digest) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  first_attempted_at TIMESTAMPTZ,
  terminal_at TIMESTAMPTZ,
  UNIQUE (run_id, id),
  UNIQUE (run_id, table_name, row_id),
  UNIQUE (run_id, sequence),
  CONSTRAINT rotation_item_run_account_fk FOREIGN KEY (run_id, account_id)
    REFERENCES rotation_runs(id, account_id) ON DELETE RESTRICT,
  CONSTRAINT rotation_item_paths_allowed CHECK (
    target_paths <@ public.rotation_allowed_paths(table_name)
  )
);

CREATE TABLE rotation_manifests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL REFERENCES rotation_runs(id) ON DELETE RESTRICT,
  revision INTEGER NOT NULL CHECK (revision > 0),
  preparer_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
  prepared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  manifest_digest BYTEA NOT NULL CHECK (octet_length(manifest_digest) = 32),
  entry_count INTEGER NOT NULL CHECK (entry_count > 0),
  UNIQUE (run_id, revision)
);

CREATE TABLE rotation_manifest_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  manifest_id UUID NOT NULL REFERENCES rotation_manifests(id) ON DELETE RESTRICT,
  run_id UUID NOT NULL REFERENCES rotation_runs(id) ON DELETE RESTRICT,
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  table_name TEXT NOT NULL
    CONSTRAINT rotation_manifest_entry_table_check CHECK (
      table_name IN ('whatsapp_config', 'salesforce_config', 'ai_configs', 'webhook_endpoints')
    ),
  row_id UUID NOT NULL,
  value_path TEXT NOT NULL,
  value_format TEXT NOT NULL
    CONSTRAINT rotation_manifest_format_check CHECK (value_format IN ('gcm', 'cbc')),
  legacy_owner TEXT NOT NULL
    CONSTRAINT rotation_manifest_owner_check CHECK (
      legacy_owner IN ('current', 'previous', 'unknown')
    ),
  value_digest BYTEA NOT NULL CHECK (octet_length(value_digest) = 32),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (manifest_id, table_name, row_id, value_path),
  CONSTRAINT rotation_manifest_path_allowed CHECK (
    value_path = ANY(public.rotation_allowed_paths(table_name))
  )
);

CREATE TABLE rotation_manifest_approvals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  manifest_id UUID NOT NULL UNIQUE REFERENCES rotation_manifests(id) ON DELETE RESTRICT,
  run_id UUID NOT NULL REFERENCES rotation_runs(id) ON DELETE RESTRICT,
  manifest_digest BYTEA NOT NULL CHECK (octet_length(manifest_digest) = 32),
  decision TEXT NOT NULL
    CONSTRAINT rotation_manifest_decision_check CHECK (decision IN ('approved', 'rejected')),
  approver_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
  approved_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rotation_audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID REFERENCES rotation_runs(id) ON DELETE RESTRICT,
  item_id UUID,
  account_id UUID REFERENCES accounts(id) ON DELETE RESTRICT,
  actor_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL
    CONSTRAINT rotation_audit_event_type_check CHECK (
      event_type IN (
        'operations_enabled', 'operations_disabled', 'run_created', 'run_started',
        'manifest_imported', 'manifest_replayed', 'manifest_approved', 'manifest_rejected',
        'item_applied', 'item_replayed', 'item_conflict', 'item_missing',
        'item_rejected', 'run_completed', 'gate_failed', 'key_retired',
        'manifest_purged'
      )
    ),
  status TEXT NOT NULL
    CONSTRAINT rotation_audit_status_check CHECK (
      status IN ('planned', 'accepted', 'applied', 'blocked', 'failed', 'completed')
    ),
  reason_code TEXT NOT NULL
    CONSTRAINT rotation_audit_reason_check CHECK (
      reason_code IN (
        'none', 'created', 'started', 'applied', 'already_applied',
        'manifest_pending', 'manifest_reimported', 'manifest_replayed',
        'version_conflict', 'row_missing', 'invalid_payload',
        'approval_required', 'unknown_ownership', 'digest_mismatch',
        'role_collision', 'operations_disabled', 'payload_mismatch',
        'count_mismatch', 'inventory_changed', 'zero_inventory',
        'already_purged', 'operator_disabled', 'mode_read_only',
        'incident_response', 'maintenance', 'fix_forward', 'completed',
        'gate_failed', 'retention_active'
      )
    ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT rotation_audit_item_fk FOREIGN KEY (run_id, item_id)
    REFERENCES rotation_items(run_id, id) ON DELETE RESTRICT
);

CREATE INDEX rotation_runs_status_created_idx
  ON rotation_runs (status, created_at);
CREATE INDEX rotation_runs_purge_after_idx
  ON rotation_runs (purge_after) WHERE purge_after IS NOT NULL;
CREATE INDEX rotation_items_run_sequence_idx
  ON rotation_items (run_id, sequence);
CREATE INDEX rotation_items_run_status_idx
  ON rotation_items (run_id, status);
CREATE INDEX rotation_manifest_entries_run_row_idx
  ON rotation_manifest_entries (run_id, table_name, row_id);
CREATE INDEX rotation_audit_events_run_created_idx
  ON rotation_audit_events (run_id, created_at);

ALTER TABLE rotation_runtime_control ENABLE ROW LEVEL SECURITY;
ALTER TABLE rotation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE rotation_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE rotation_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE rotation_manifest_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE rotation_manifest_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE rotation_audit_events ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE rotation_runtime_control FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE rotation_runs FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE rotation_items FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE rotation_manifests FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE rotation_manifest_entries FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE rotation_manifest_approvals FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE rotation_audit_events FROM PUBLIC, anon, authenticated, service_role;

GRANT SELECT, UPDATE ON rotation_runtime_control TO key_rotation_executor;
GRANT SELECT, INSERT, UPDATE ON rotation_runs, rotation_items TO key_rotation_executor;
GRANT SELECT, INSERT, DELETE ON rotation_manifests, rotation_manifest_entries,
  rotation_manifest_approvals TO key_rotation_executor;
GRANT SELECT, INSERT, UPDATE, DELETE ON rotation_audit_events TO key_rotation_executor;
GRANT DELETE ON rotation_items TO key_rotation_executor;
GRANT SELECT, UPDATE ON whatsapp_config, salesforce_config, ai_configs,
  webhook_endpoints TO key_rotation_executor;
GRANT SELECT ON profiles TO key_rotation_executor;

-- Every state-changing operation follows the same deadlock-safe order:
-- LOCK ORDER: control -> account barrier -> run -> item -> encrypted row.
-- Locks are transaction-scoped and every caller re-reads state after acquiring
-- them. Private helpers are not executable by API roles.
CREATE FUNCTION public.lock_key_rotation_control()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_singleton BOOLEAN;
BEGIN
  SELECT control.singleton
  INTO v_singleton
  FROM public.rotation_runtime_control AS control
  WHERE control.singleton
  FOR UPDATE;
  RETURN COALESCE(v_singleton, FALSE);
END;
$$;

CREATE FUNCTION public.lock_key_rotation_run(p_run_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_run_id UUID;
BEGIN
  SELECT run.id
  INTO v_run_id
  FROM public.rotation_runs AS run
  WHERE run.id = p_run_id
  FOR UPDATE;
  RETURN v_run_id IS NOT NULL;
END;
$$;

CREATE FUNCTION public.refresh_key_rotation_accounting(p_run_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  UPDATE public.rotation_runs AS run
  SET visited_items = accounting.visited_items,
      terminal_items = accounting.terminal_items,
      applied_values = accounting.applied_values,
      failed_values = accounting.failed_values
  FROM (
    SELECT
      COUNT(*) FILTER (WHERE item.attempts > 0)::BIGINT AS visited_items,
       COUNT(*) FILTER (
        WHERE item.status IN ('applied', 'conflict', 'missing', 'blocked')
      )::BIGINT AS terminal_items,
      COALESCE(SUM(cardinality(item.target_paths)) FILTER (
        WHERE item.status = 'applied'
      ), 0)::BIGINT AS applied_values,
      COALESCE(SUM(cardinality(item.target_paths)) FILTER (
        WHERE item.status IN ('conflict', 'missing', 'blocked')
      ), 0)::BIGINT AS failed_values
    FROM public.rotation_items AS item
    WHERE item.run_id = p_run_id
  ) AS accounting
  WHERE run.id = p_run_id;
END;
$$;

ALTER FUNCTION public.lock_key_rotation_control() OWNER TO key_rotation_executor;
ALTER FUNCTION public.lock_key_rotation_run(UUID) OWNER TO key_rotation_executor;
ALTER FUNCTION public.refresh_key_rotation_accounting(UUID) OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION public.lock_key_rotation_control()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.lock_key_rotation_run(UUID)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.refresh_key_rotation_accounting(UUID)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION public.disable_key_rotation_operations(p_reason TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '8s'
SET statement_timeout = '30s'
AS $$
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;
  IF p_reason NOT IN (
    'operator_disabled', 'incident_response', 'maintenance', 'fix_forward'
  ) THEN
    RAISE EXCEPTION 'invalid key rotation reason' USING ERRCODE = '22023';
  END IF;

  PERFORM public.lock_key_rotation_control();

  UPDATE public.rotation_runtime_control
  SET operations_enabled = FALSE,
      disabled_reason = p_reason,
      updated_by = auth.uid(),
      updated_at = now()
  WHERE singleton;

  INSERT INTO public.rotation_audit_events (
    actor_id, event_type, status, reason_code
  ) VALUES (
    auth.uid(), 'operations_disabled', 'accepted', p_reason
  );
END;
$$;

CREATE FUNCTION public.assert_key_rotation_rollback_safe()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;
  PERFORM public.lock_key_rotation_control();
  IF (SELECT operations_enabled FROM public.rotation_runtime_control WHERE singleton) THEN
    RAISE EXCEPTION 'key rotation must be disabled before rollback' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (SELECT 1 FROM public.rotation_runs) THEN
    RAISE EXCEPTION 'retained key rotation evidence blocks destructive rollback'
      USING ERRCODE = '55000';
  END IF;
END;
$$;

ALTER FUNCTION public.disable_key_rotation_operations(TEXT) OWNER TO key_rotation_executor;
ALTER FUNCTION public.assert_key_rotation_rollback_safe() OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION public.disable_key_rotation_operations(TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.assert_key_rotation_rollback_safe() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.disable_key_rotation_operations(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.assert_key_rotation_rollback_safe() TO service_role;

-- No DROP statements belong in this production migration. If a fix-forward
-- rollback is ever proposed, call assert_key_rotation_rollback_safe() first;
-- retained or active evidence deliberately blocks destructive reversal.

-- Digest matching is internal and returns only a boolean. It never exposes the
-- stored value or its digest through an API response.
CREATE FUNCTION public.rotation_manifest_entry_digest_matches(
  p_entry public.rotation_manifest_entries
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_stored_value TEXT;
BEGIN
  CASE p_entry.table_name
    WHEN 'whatsapp_config' THEN
      SELECT CASE p_entry.value_path
        WHEN 'access_token' THEN access_token
        WHEN 'verify_token' THEN verify_token
        WHEN 'provider_config.apiKey' THEN provider_config ->> 'apiKey'
        WHEN 'provider_config.secret' THEN provider_config ->> 'secret'
      END
      INTO v_stored_value
      FROM public.whatsapp_config
      WHERE id = p_entry.row_id AND account_id = p_entry.account_id;
    WHEN 'salesforce_config' THEN
      SELECT CASE p_entry.value_path
        WHEN 'client_id' THEN client_id
        WHEN 'client_secret' THEN client_secret
        WHEN 'username' THEN username
        WHEN 'password' THEN password
        WHEN 'security_token' THEN security_token
        WHEN 'webhook_secret' THEN webhook_secret
      END
      INTO v_stored_value
      FROM public.salesforce_config
      WHERE id = p_entry.row_id AND account_id = p_entry.account_id;
    WHEN 'ai_configs' THEN
      SELECT CASE p_entry.value_path
        WHEN 'api_key' THEN api_key
        WHEN 'embeddings_api_key' THEN embeddings_api_key
      END
      INTO v_stored_value
      FROM public.ai_configs
      WHERE id = p_entry.row_id AND account_id = p_entry.account_id;
    WHEN 'webhook_endpoints' THEN
      SELECT secret
      INTO v_stored_value
      FROM public.webhook_endpoints
      WHERE id = p_entry.row_id AND account_id = p_entry.account_id
        AND p_entry.value_path = 'secret';
    ELSE
      RETURN FALSE;
  END CASE;

  RETURN v_stored_value IS NOT NULL AND
    CASE p_entry.value_format
      WHEN 'gcm' THEN
        v_stored_value ~ '^[0-9a-f]{24}:[0-9a-f]*:[0-9a-f]{32}$'
      WHEN 'cbc' THEN
        v_stored_value ~ '^[0-9a-f]{32}:[0-9a-f]+$'
      ELSE FALSE
    END AND
    extensions.digest(convert_to(v_stored_value, 'UTF8'), 'sha256') = p_entry.value_digest;
END;
$$;

CREATE FUNCTION public.rotation_item_has_approved_manifest(
  p_run_id UUID,
  p_item_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_manifest_id UUID;
  v_item public.rotation_items%ROWTYPE;
BEGIN
  SELECT m.id
  INTO v_manifest_id
  FROM public.rotation_manifests m
  WHERE m.run_id = p_run_id
  ORDER BY revision DESC
  LIMIT 1;

  IF v_manifest_id IS NULL OR NOT EXISTS (
    SELECT 1
    FROM public.rotation_manifest_approvals a
    JOIN public.rotation_manifests m ON m.id = a.manifest_id
    WHERE a.manifest_id = v_manifest_id
      AND a.run_id = p_run_id
      AND a.manifest_digest = m.manifest_digest
      AND a.decision = 'approved'
  ) THEN
    RETURN FALSE;
  END IF;

  SELECT * INTO v_item
  FROM public.rotation_items
  WHERE run_id = p_run_id AND id = p_item_id;
  IF NOT FOUND THEN
    RETURN FALSE;
  END IF;

  RETURN NOT EXISTS (
    SELECT 1
    FROM unnest(v_item.target_paths) AS required(value_path)
    LEFT JOIN public.rotation_manifest_entries e
      ON e.manifest_id = v_manifest_id
     AND e.run_id = v_item.run_id
     AND e.account_id = v_item.account_id
     AND e.table_name = v_item.table_name
     AND e.row_id = v_item.row_id
     AND e.value_path = required.value_path
    WHERE e.id IS NULL
       OR e.legacy_owner = 'unknown'
       OR (e.value_format = 'gcm' AND e.legacy_owner <> 'current')
       OR (e.value_format = 'cbc' AND e.legacy_owner NOT IN ('current', 'previous'))
  );
END;
$$;

CREATE FUNCTION public.rotation_item_matches_applied_metadata(
  p_item public.rotation_items
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_matches BOOLEAN := FALSE;
BEGIN
  CASE p_item.table_name
    WHEN 'whatsapp_config' THEN
      SELECT TRUE INTO v_matches FROM public.whatsapp_config AS encrypted_row
      WHERE encrypted_row.id = p_item.row_id
        AND encrypted_row.account_id = p_item.account_id
        AND encrypted_row.secret_version = p_item.applied_version
        AND encrypted_row.secret_fingerprint = p_item.applied_fingerprint
      FOR UPDATE;
    WHEN 'salesforce_config' THEN
      SELECT TRUE INTO v_matches FROM public.salesforce_config AS encrypted_row
      WHERE encrypted_row.id = p_item.row_id
        AND encrypted_row.account_id = p_item.account_id
        AND encrypted_row.secret_version = p_item.applied_version
        AND encrypted_row.secret_fingerprint = p_item.applied_fingerprint
      FOR UPDATE;
    WHEN 'ai_configs' THEN
      SELECT TRUE INTO v_matches FROM public.ai_configs AS encrypted_row
      WHERE encrypted_row.id = p_item.row_id
        AND encrypted_row.account_id = p_item.account_id
        AND encrypted_row.secret_version = p_item.applied_version
        AND encrypted_row.secret_fingerprint = p_item.applied_fingerprint
      FOR UPDATE;
    WHEN 'webhook_endpoints' THEN
      SELECT TRUE INTO v_matches FROM public.webhook_endpoints AS encrypted_row
      WHERE encrypted_row.id = p_item.row_id
        AND encrypted_row.account_id = p_item.account_id
        AND encrypted_row.secret_version = p_item.applied_version
        AND encrypted_row.secret_fingerprint = p_item.applied_fingerprint
      FOR UPDATE;
    ELSE v_matches := FALSE;
  END CASE;
  RETURN COALESCE(v_matches, FALSE);
END;
$$;

ALTER FUNCTION public.rotation_manifest_entry_digest_matches(public.rotation_manifest_entries)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.rotation_item_has_approved_manifest(UUID, UUID)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.rotation_item_matches_applied_metadata(public.rotation_items)
  OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION public.rotation_manifest_entry_digest_matches(public.rotation_manifest_entries)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.rotation_item_has_approved_manifest(UUID, UUID)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.rotation_item_matches_applied_metadata(public.rotation_items)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION public.reject_key_rotation_item(
  p_run_id UUID,
  p_item_id UUID,
  p_account_id UUID,
  p_reason_code TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  UPDATE public.rotation_items
  SET status = 'blocked',
      reason_code = p_reason_code,
      attempts = attempts + 1,
      first_attempted_at = COALESCE(first_attempted_at, now()),
      terminal_at = now()
  WHERE run_id = p_run_id AND id = p_item_id;

  INSERT INTO public.rotation_audit_events (
    run_id, item_id, account_id, actor_id, event_type, status, reason_code
  ) VALUES (
    p_run_id, p_item_id, p_account_id, auth.uid(),
    'item_rejected', 'blocked', p_reason_code
  );
  PERFORM public.refresh_key_rotation_accounting(p_run_id);
END;
$$;

ALTER FUNCTION public.reject_key_rotation_item(UUID, UUID, UUID, TEXT)
  OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION public.reject_key_rotation_item(UUID, UUID, UUID, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;

-- ============================================================
-- Task 4.2 — atomic, idempotent, service-role-only row rotation
-- ============================================================
CREATE FUNCTION public.rotate_encrypted_row(
  p_run_id UUID,
  p_item_id UUID,
  p_table TEXT,
  p_row_id UUID,
  p_expected_version BIGINT,
  p_expected_fingerprint UUID,
  p_values JSONB
)
RETURNS TABLE (
  outcome TEXT,
  account_id UUID,
  new_version BIGINT,
  new_fingerprint UUID,
  reason_code TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '8s'
SET statement_timeout = '30s'
AS $$
DECLARE
  v_operations_enabled BOOLEAN;
  v_run_status TEXT;
  v_run_mode TEXT;
  v_item_status TEXT;
  v_item_table TEXT;
  v_item_row_id UUID;
  v_account_id UUID;
  v_run_account_id UUID;
  v_expected_version BIGINT;
  v_expected_fingerprint UUID;
  v_target_paths TEXT[];
  v_replacement_payload_digest BYTEA;
  v_payload_paths TEXT[];
  v_new_version BIGINT;
  v_new_fingerprint UUID;
  v_payload_digest BYTEA;
  v_row_exists BOOLEAN := FALSE;
  v_max_ciphertext_bytes CONSTANT INTEGER := 16 * 1024;
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;

  PERFORM public.lock_key_rotation_control();
  SELECT run.account_id
  INTO v_run_account_id
  FROM public.rotation_runs AS run
  WHERE run.id = p_run_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT
      'rejected'::TEXT, NULL::UUID, NULL::BIGINT, NULL::UUID,
      'invalid_payload'::TEXT;
    RETURN;
  END IF;
  PERFORM public.lock_key_rotation_account(v_run_account_id);
  IF NOT public.lock_key_rotation_run(p_run_id) THEN
    RETURN QUERY SELECT
      'rejected'::TEXT, NULL::UUID, NULL::BIGINT, NULL::UUID,
      'invalid_payload'::TEXT;
    RETURN;
  END IF;

  SELECT run.status, run.mode, run.account_id
  INTO v_run_status, v_run_mode, v_run_account_id
  FROM public.rotation_runs AS run
  WHERE run.id = p_run_id;

  SELECT operations_enabled
  INTO v_operations_enabled
   FROM public.rotation_runtime_control
  WHERE singleton;

  SELECT
    i.status,
    i.table_name,
    i.row_id,
    i.account_id,
    i.expected_version,
    i.expected_fingerprint,
    i.target_paths,
    i.replacement_payload_digest
  INTO
    v_item_status,
    v_item_table,
    v_item_row_id,
    v_account_id,
    v_expected_version,
    v_expected_fingerprint,
    v_target_paths,
    v_replacement_payload_digest
   FROM public.rotation_items i
  WHERE i.run_id = p_run_id
    AND i.id = p_item_id
  FOR UPDATE OF i;

  IF NOT FOUND OR v_item_table IS DISTINCT FROM p_table OR
     v_item_row_id IS DISTINCT FROM p_row_id OR
     v_expected_version IS DISTINCT FROM p_expected_version OR
     v_expected_fingerprint IS DISTINCT FROM p_expected_fingerprint THEN
    INSERT INTO public.rotation_audit_events (
      run_id, item_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id,
      CASE WHEN FOUND THEN p_item_id ELSE NULL END,
      COALESCE(v_account_id, v_run_account_id),
      auth.uid(), 'item_rejected', 'blocked', 'invalid_payload'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, COALESCE(v_account_id, v_run_account_id),
      NULL::BIGINT, NULL::UUID,
      'invalid_payload'::TEXT;
    RETURN;
  END IF;

  -- Idempotent replay is checked before any terminal state rejection: a
  -- transient failure or a crash after the row was applied but before the
  -- audit event was written must resolve to 'already_applied' even when the
  -- run is no longer in 'running'/'apply' mode. Otherwise every retry would
  -- misreport a fully-applied item as rejected.
  v_payload_digest := extensions.digest(
    convert_to(p_values::TEXT, 'UTF8'),
    'sha256'
  );

  IF v_item_status = 'applied' THEN
    IF v_replacement_payload_digest IS DISTINCT FROM v_payload_digest THEN
      INSERT INTO public.rotation_audit_events (
        run_id, item_id, account_id, actor_id, event_type, status, reason_code
      ) VALUES (
        p_run_id, p_item_id, v_account_id, auth.uid(),
        'item_conflict', 'blocked', 'payload_mismatch'
      );
      RETURN QUERY SELECT
        'conflict'::TEXT,
        v_account_id,
        NULL::BIGINT,
        NULL::UUID,
        'payload_mismatch'::TEXT;
      RETURN;
    END IF;

    IF NOT public.rotation_item_matches_applied_metadata(
      (SELECT item FROM public.rotation_items AS item
       WHERE item.run_id = p_run_id AND item.id = p_item_id)
    ) THEN
      INSERT INTO public.rotation_audit_events (
        run_id, item_id, account_id, actor_id, event_type, status, reason_code
      ) VALUES (
        p_run_id, p_item_id, v_account_id, auth.uid(),
        'item_conflict', 'blocked', 'version_conflict'
      );
      RETURN QUERY SELECT
        'conflict'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
        'version_conflict'::TEXT;
      RETURN;
    END IF;

    INSERT INTO public.rotation_audit_events (
      run_id, item_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, p_item_id, v_account_id, auth.uid(),
      'item_replayed', 'accepted', 'already_applied'
    );
    RETURN QUERY
    SELECT
      'already_applied'::TEXT,
      v_account_id,
      i.applied_version,
      i.applied_fingerprint,
      'already_applied'::TEXT
    FROM public.rotation_items i
    WHERE i.run_id = p_run_id AND i.id = p_item_id;
    RETURN;
  END IF;

  IF v_run_mode IS DISTINCT FROM 'apply' THEN
    PERFORM public.reject_key_rotation_item(
      p_run_id, p_item_id, v_account_id, 'mode_read_only'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
      'mode_read_only'::TEXT;
    RETURN;
  END IF;

  IF v_run_status IS DISTINCT FROM 'running' THEN
    PERFORM public.reject_key_rotation_item(
      p_run_id, p_item_id, v_account_id, 'approval_required'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
      'approval_required'::TEXT;
    RETURN;
  END IF;

  IF NOT COALESCE(v_operations_enabled, FALSE) THEN
    PERFORM public.reject_key_rotation_item(
      p_run_id, p_item_id, v_account_id, 'operations_disabled'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
      'operations_disabled'::TEXT;
    RETURN;
  END IF;

  IF NOT public.rotation_item_has_approved_manifest(p_run_id, p_item_id) THEN
    PERFORM public.reject_key_rotation_item(
      p_run_id, p_item_id, v_account_id, 'approval_required'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
      'approval_required'::TEXT;
    RETURN;
  END IF;

  IF jsonb_typeof(p_values) IS DISTINCT FROM 'object' THEN
    PERFORM public.reject_key_rotation_item(
      p_run_id, p_item_id, v_account_id, 'invalid_payload'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
      'invalid_payload'::TEXT;
    RETURN;
  END IF;

  SELECT array_agg(key ORDER BY key)
  INTO v_payload_paths
  FROM jsonb_object_keys(p_values) AS keys(key);

  IF v_payload_paths IS DISTINCT FROM (
    SELECT array_agg(DISTINCT path ORDER BY path)
    FROM unnest(v_target_paths) AS paths(path)
  ) THEN
    PERFORM public.reject_key_rotation_item(
      p_run_id, p_item_id, v_account_id, 'invalid_payload'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
      'invalid_payload'::TEXT;
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM jsonb_each(p_values) AS values_to_validate(path, encoded_value)
    WHERE jsonb_typeof(encoded_value) <> 'string'
       OR octet_length(encoded_value #>> '{}') > v_max_ciphertext_bytes
       OR encoded_value #>> '{}' !~ '^[0-9a-f]{24}:[0-9a-f]*:[0-9a-f]{32}$'
  ) THEN
    PERFORM public.reject_key_rotation_item(
      p_run_id, p_item_id, v_account_id, 'invalid_payload'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
      'invalid_payload'::TEXT;
    RETURN;
  END IF;

  -- Closed CASE p_table allow-list. No identifier or value is interpolated.
  CASE p_table
    WHEN 'whatsapp_config' THEN
      UPDATE public.whatsapp_config AS w
      SET access_token = CASE
            WHEN p_values ? 'access_token' THEN p_values ->> 'access_token'
            ELSE w.access_token
          END,
          verify_token = CASE
            WHEN p_values ? 'verify_token' THEN p_values ->> 'verify_token'
            ELSE w.verify_token
          END,
          provider_config = CASE
            WHEN p_values ? 'provider_config.apiKey' AND
                 p_values ? 'provider_config.secret' THEN
              jsonb_set(
                jsonb_set(
                  COALESCE(w.provider_config, '{}'::JSONB),
                  '{apiKey}',
                  to_jsonb(p_values ->> 'provider_config.apiKey'),
                  TRUE
                ),
                '{secret}',
                to_jsonb(p_values ->> 'provider_config.secret'),
                TRUE
              )
            WHEN p_values ? 'provider_config.apiKey' THEN
              jsonb_set(
                COALESCE(w.provider_config, '{}'::JSONB),
                '{apiKey}',
                to_jsonb(p_values ->> 'provider_config.apiKey'),
                TRUE
              )
            WHEN p_values ? 'provider_config.secret' THEN
              jsonb_set(
                COALESCE(w.provider_config, '{}'::JSONB),
                '{secret}',
                to_jsonb(p_values ->> 'provider_config.secret'),
                TRUE
              )
            ELSE w.provider_config
          END
      WHERE w.id = p_row_id
        AND w.account_id = v_account_id
        AND w.secret_version = p_expected_version
        AND w.secret_fingerprint = p_expected_fingerprint
      RETURNING w.account_id, w.secret_version, w.secret_fingerprint
      INTO v_account_id, v_new_version, v_new_fingerprint;

    WHEN 'salesforce_config' THEN
      UPDATE public.salesforce_config AS s
      SET client_id = CASE WHEN p_values ? 'client_id'
            THEN p_values ->> 'client_id' ELSE s.client_id END,
          client_secret = CASE WHEN p_values ? 'client_secret'
            THEN p_values ->> 'client_secret' ELSE s.client_secret END,
          username = CASE WHEN p_values ? 'username'
            THEN p_values ->> 'username' ELSE s.username END,
          password = CASE WHEN p_values ? 'password'
            THEN p_values ->> 'password' ELSE s.password END,
          security_token = CASE WHEN p_values ? 'security_token'
            THEN p_values ->> 'security_token' ELSE s.security_token END,
          webhook_secret = CASE WHEN p_values ? 'webhook_secret'
            THEN p_values ->> 'webhook_secret' ELSE s.webhook_secret END
      WHERE s.id = p_row_id
        AND s.account_id = v_account_id
        AND s.secret_version = p_expected_version
        AND s.secret_fingerprint = p_expected_fingerprint
      RETURNING s.account_id, s.secret_version, s.secret_fingerprint
      INTO v_account_id, v_new_version, v_new_fingerprint;

    WHEN 'ai_configs' THEN
      UPDATE public.ai_configs AS a
      SET api_key = CASE WHEN p_values ? 'api_key'
            THEN p_values ->> 'api_key' ELSE a.api_key END,
          embeddings_api_key = CASE WHEN p_values ? 'embeddings_api_key'
            THEN p_values ->> 'embeddings_api_key' ELSE a.embeddings_api_key END
      WHERE a.id = p_row_id
        AND a.account_id = v_account_id
        AND a.secret_version = p_expected_version
        AND a.secret_fingerprint = p_expected_fingerprint
      RETURNING a.account_id, a.secret_version, a.secret_fingerprint
      INTO v_account_id, v_new_version, v_new_fingerprint;

    WHEN 'webhook_endpoints' THEN
      UPDATE public.webhook_endpoints AS h
      SET secret = p_values ->> 'secret'
      WHERE h.id = p_row_id
        AND h.account_id = v_account_id
        AND h.secret_version = p_expected_version
        AND h.secret_fingerprint = p_expected_fingerprint
      RETURNING h.account_id, h.secret_version, h.secret_fingerprint
      INTO v_account_id, v_new_version, v_new_fingerprint;

    ELSE
      RETURN QUERY SELECT
        'rejected'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
        'invalid_payload'::TEXT;
      RETURN;
  END CASE;

  IF v_new_version IS NULL THEN
    CASE p_table
      WHEN 'whatsapp_config' THEN
        SELECT EXISTS (SELECT 1 FROM public.whatsapp_config w
          WHERE w.id = p_row_id AND w.account_id = v_account_id) INTO v_row_exists;
      WHEN 'salesforce_config' THEN
        SELECT EXISTS (SELECT 1 FROM public.salesforce_config s
          WHERE s.id = p_row_id AND s.account_id = v_account_id) INTO v_row_exists;
      WHEN 'ai_configs' THEN
        SELECT EXISTS (SELECT 1 FROM public.ai_configs a
          WHERE a.id = p_row_id AND a.account_id = v_account_id) INTO v_row_exists;
      WHEN 'webhook_endpoints' THEN
        SELECT EXISTS (SELECT 1 FROM public.webhook_endpoints h
          WHERE h.id = p_row_id AND h.account_id = v_account_id) INTO v_row_exists;
      ELSE v_row_exists := FALSE;
    END CASE;

    UPDATE public.rotation_items
    SET status = CASE WHEN v_row_exists THEN 'conflict' ELSE 'missing' END,
        reason_code = CASE
          WHEN v_row_exists THEN 'version_conflict' ELSE 'row_missing'
        END,
        attempts = attempts + 1,
        first_attempted_at = COALESCE(first_attempted_at, now()),
        terminal_at = now()
    WHERE run_id = p_run_id AND id = p_item_id;

    INSERT INTO public.rotation_audit_events (
      run_id, item_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, p_item_id, v_account_id, auth.uid(),
      CASE WHEN v_row_exists THEN 'item_conflict' ELSE 'item_missing' END,
      'blocked',
      CASE WHEN v_row_exists THEN 'version_conflict' ELSE 'row_missing' END
    );
    PERFORM public.refresh_key_rotation_accounting(p_run_id);

    RETURN QUERY SELECT
      CASE WHEN v_row_exists THEN 'conflict' ELSE 'missing' END::TEXT,
      v_account_id,
      NULL::BIGINT,
      NULL::UUID,
      CASE WHEN v_row_exists THEN 'version_conflict' ELSE 'row_missing' END::TEXT;
    RETURN;
  END IF;

  UPDATE public.rotation_items
  SET status = 'applied',
      reason_code = 'applied',
      attempts = attempts + 1,
      first_attempted_at = COALESCE(first_attempted_at, now()),
       applied_version = v_new_version,
       applied_fingerprint = v_new_fingerprint,
       replacement_payload_digest = v_payload_digest,
       terminal_at = now()
  WHERE run_id = p_run_id AND id = p_item_id;

  INSERT INTO public.rotation_audit_events (
    run_id, item_id, account_id, actor_id, event_type, status, reason_code
  ) VALUES (
    p_run_id, p_item_id, v_account_id, auth.uid(),
    'item_applied', 'applied', 'applied'
  );
  PERFORM public.refresh_key_rotation_accounting(p_run_id);

  RETURN QUERY SELECT
    'applied'::TEXT,
    v_account_id,
    v_new_version,
    v_new_fingerprint,
    'applied'::TEXT;
END;
$$;

ALTER FUNCTION public.rotate_encrypted_row(
  UUID, UUID, TEXT, UUID, BIGINT, UUID, JSONB
) OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION public.rotate_encrypted_row(
  UUID, UUID, TEXT, UUID, BIGINT, UUID, JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rotate_encrypted_row(
  UUID, UUID, TEXT, UUID, BIGINT, UUID, JSONB
) TO service_role;

-- ============================================================
-- Task 4.3 — immutable row/path ownership evidence and dual control
-- ============================================================
CREATE FUNCTION public.import_rotation_manifest(
  p_run_id UUID,
  p_manifest_digest TEXT,
  p_entries JSONB
)
RETURNS TABLE (
  manifest_id UUID,
  revision INTEGER,
  manifest_digest TEXT,
  status TEXT,
  reason_code TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_preparer_id UUID := auth.uid();
  v_run_account_id UUID;
  v_run_status TEXT;
  v_manifest_id UUID;
  v_revision INTEGER;
  v_prior_revisions INTEGER;
  v_canonical_entries JSONB;
  v_computed_digest BYTEA;
  v_submitted_digest BYTEA;
  v_existing_manifest_id UUID;
  v_existing_revision INTEGER;
  v_existing_status TEXT;
BEGIN
  IF auth.role() IS DISTINCT FROM 'authenticated' OR v_preparer_id IS NULL THEN
    RAISE EXCEPTION 'manifest authorization failed' USING ERRCODE = '42501';
  END IF;
  IF p_manifest_digest !~ '^[0-9a-f]{64}$' OR
     jsonb_typeof(p_entries) <> 'array' OR
     jsonb_array_length(p_entries) = 0 THEN
    RAISE EXCEPTION 'invalid manifest evidence' USING ERRCODE = '22023';
  END IF;

  PERFORM public.lock_key_rotation_control();
  IF NOT public.lock_key_rotation_run(p_run_id) THEN
    RAISE EXCEPTION 'manifest authorization failed' USING ERRCODE = '42501';
  END IF;

  SELECT account_id, status INTO v_run_account_id, v_run_status
  FROM public.rotation_runs
  WHERE id = p_run_id
  FOR UPDATE;
  IF NOT FOUND OR v_run_status IN ('completed', 'retired') OR NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE user_id = v_preparer_id
      AND account_id = v_run_account_id
      AND account_role IN ('owner', 'admin')
  ) THEN
    RAISE EXCEPTION 'manifest authorization failed' USING ERRCODE = '42501';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(p_entries) AS entries(entry)
    WHERE (entry - ARRAY[
      'account_id', 'table_name', 'row_id', 'value_path', 'value_format',
      'legacy_owner', 'value_digest'
    ]::TEXT[]) <> '{}'::JSONB
       OR NOT (entry ?& ARRAY[
         'account_id', 'table_name', 'row_id', 'value_path', 'value_format',
         'legacy_owner', 'value_digest'
       ]::TEXT[])
       OR entry ->> 'account_id' <> v_run_account_id::TEXT
       OR entry ->> 'table_name' NOT IN (
         'whatsapp_config', 'salesforce_config', 'ai_configs', 'webhook_endpoints'
       )
       OR entry ->> 'value_format' NOT IN ('gcm', 'cbc')
       OR entry ->> 'legacy_owner' NOT IN ('current', 'previous', 'unknown')
       OR (entry ->> 'value_format' = 'gcm' AND entry ->> 'legacy_owner' <> 'current')
       OR entry ->> 'value_digest' !~ '^[0-9a-f]{64}$'
  ) THEN
    RAISE EXCEPTION 'invalid manifest evidence' USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(p_entries) AS entries(entry)
    GROUP BY
      entry ->> 'table_name', entry ->> 'row_id', entry ->> 'value_path'
    HAVING COUNT(*) > 1
  ) THEN
    RAISE EXCEPTION 'conflicting manifest evidence' USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(p_entries) AS entries(entry)
    WHERE NOT EXISTS (
      SELECT 1
      FROM public.rotation_items i
      WHERE i.run_id = p_run_id
        AND i.account_id = (entry ->> 'account_id')::UUID
        AND i.table_name = entry ->> 'table_name'
        AND i.row_id = (entry ->> 'row_id')::UUID
        AND entry ->> 'value_path' = ANY(i.target_paths)
    )
  ) OR EXISTS (
    SELECT 1
    FROM public.rotation_items i
    CROSS JOIN LATERAL unnest(i.target_paths) AS required(value_path)
    WHERE i.run_id = p_run_id
      AND NOT EXISTS (
        SELECT 1
        FROM jsonb_array_elements(p_entries) AS entries(entry)
        WHERE entry ->> 'account_id' = i.account_id::TEXT
          AND entry ->> 'table_name' = i.table_name
          AND entry ->> 'row_id' = i.row_id::TEXT
          AND entry ->> 'value_path' = required.value_path
      )
  ) THEN
    RAISE EXCEPTION 'manifest paths do not match rotation items'
      USING ERRCODE = '22023';
  END IF;

  SELECT jsonb_agg(entry ORDER BY
    entry ->> 'account_id', entry ->> 'table_name', entry ->> 'row_id',
    entry ->> 'value_path'
  )
  INTO v_canonical_entries
  FROM jsonb_array_elements(p_entries) AS entries(entry);

  v_computed_digest := extensions.digest(
    convert_to(v_canonical_entries::TEXT, 'UTF8'), 'sha256'
  );
  v_submitted_digest := decode(p_manifest_digest, 'hex');
  IF v_computed_digest IS DISTINCT FROM v_submitted_digest THEN
    RAISE EXCEPTION 'manifest digest mismatch' USING ERRCODE = '22000';
  END IF;

  SELECT manifest.id, manifest.revision, run.status
  INTO v_existing_manifest_id, v_existing_revision, v_existing_status
  FROM public.rotation_manifests AS manifest
  JOIN public.rotation_runs AS run ON run.id = manifest.run_id
  WHERE manifest.run_id = p_run_id
    AND manifest.manifest_digest = v_computed_digest
  ORDER BY manifest.revision DESC
  LIMIT 1;

  IF v_existing_manifest_id IS NOT NULL THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run_account_id, v_preparer_id, 'manifest_replayed',
      'accepted', 'manifest_replayed'
    );
    RETURN QUERY SELECT
      v_existing_manifest_id,
      v_existing_revision,
      encode(v_computed_digest, 'hex'),
      v_existing_status,
      'manifest_replayed'::TEXT;
    RETURN;
  END IF;

  SELECT COUNT(*), COALESCE(MAX(m.revision), 0) + 1
  INTO v_prior_revisions, v_revision
  FROM public.rotation_manifests m
  WHERE m.run_id = p_run_id;

  INSERT INTO public.rotation_manifests (
    run_id, revision, preparer_id, manifest_digest, entry_count
  ) VALUES (
    p_run_id, v_revision, v_preparer_id, v_computed_digest,
    jsonb_array_length(v_canonical_entries)
  )
  RETURNING id INTO v_manifest_id;

  INSERT INTO public.rotation_manifest_entries (
    manifest_id, run_id, account_id, table_name, row_id, value_path,
    value_format, legacy_owner, value_digest
  )
  SELECT
    v_manifest_id,
    p_run_id,
    (entry ->> 'account_id')::UUID,
    entry ->> 'table_name',
    (entry ->> 'row_id')::UUID,
    entry ->> 'value_path',
    entry ->> 'value_format',
    entry ->> 'legacy_owner',
    decode(entry ->> 'value_digest', 'hex')
  FROM jsonb_array_elements(v_canonical_entries) AS entries(entry);

  UPDATE public.rotation_runs
  SET status = 'awaiting_approval',
      reason_code = CASE
        WHEN v_prior_revisions > 0 THEN 'manifest_reimported'
        ELSE 'manifest_pending'
      END
  WHERE id = p_run_id;

  INSERT INTO public.rotation_audit_events (
    run_id, account_id, actor_id, event_type, status, reason_code
  ) VALUES (
    p_run_id, v_run_account_id, v_preparer_id, 'manifest_imported',
    'accepted',
    CASE WHEN v_prior_revisions > 0
      THEN 'manifest_reimported' ELSE 'manifest_pending' END
  );

  RETURN QUERY SELECT
    v_manifest_id,
    v_revision,
    encode(v_computed_digest, 'hex'),
    'awaiting_approval'::TEXT,
    CASE WHEN v_prior_revisions > 0
      THEN 'manifest_reimported' ELSE 'manifest_pending' END::TEXT;
END;
$$;

CREATE FUNCTION public.approve_rotation_manifest(
  p_run_id UUID,
  p_manifest_digest TEXT,
  p_decision TEXT
)
RETURNS TABLE (
  outcome TEXT,
  reason_code TEXT,
  manifest_id UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_approver_id UUID := auth.uid();
  v_manifest_id UUID;
  v_preparer_id UUID;
  v_run_account_id UUID;
  v_run_status TEXT;
  v_stored_digest BYTEA;
  v_existing_decision TEXT;
BEGIN
  IF auth.role() IS DISTINCT FROM 'authenticated' OR v_approver_id IS NULL THEN
    RAISE EXCEPTION 'manifest authorization failed' USING ERRCODE = '42501';
  END IF;
  IF p_manifest_digest !~ '^[0-9a-f]{64}$' OR
     p_decision NOT IN ('approved', 'rejected') THEN
    RAISE EXCEPTION 'invalid approval evidence' USING ERRCODE = '22023';
  END IF;

  PERFORM public.lock_key_rotation_control();
  IF NOT public.lock_key_rotation_run(p_run_id) THEN
    RAISE EXCEPTION 'manifest authorization failed' USING ERRCODE = '42501';
  END IF;

  SELECT m.id, m.preparer_id, m.manifest_digest, r.account_id, r.status
  INTO v_manifest_id, v_preparer_id, v_stored_digest, v_run_account_id,
    v_run_status
  FROM public.rotation_manifests m
  JOIN public.rotation_runs r ON r.id = m.run_id
  WHERE m.run_id = p_run_id
  ORDER BY revision DESC
  LIMIT 1
  FOR UPDATE OF m;

  IF NOT FOUND OR v_run_status NOT IN ('awaiting_approval', 'approved', 'blocked') OR NOT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE user_id = v_approver_id
      AND account_id = v_run_account_id
      AND account_role IN ('owner', 'admin')
  ) THEN
    RAISE EXCEPTION 'manifest authorization failed' USING ERRCODE = '42501';
  END IF;

  IF v_preparer_id = v_approver_id THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run_account_id, v_approver_id,
      'manifest_rejected', 'blocked', 'role_collision'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, 'role_collision'::TEXT, v_manifest_id;
    RETURN;
  END IF;

  IF v_stored_digest IS DISTINCT FROM decode(p_manifest_digest, 'hex') THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run_account_id, v_approver_id,
      'manifest_rejected', 'blocked', 'digest_mismatch'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, 'digest_mismatch'::TEXT, v_manifest_id;
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.rotation_manifest_approvals
    WHERE rotation_manifest_approvals.manifest_id = v_manifest_id
  ) THEN
    SELECT decision INTO v_existing_decision
    FROM public.rotation_manifest_approvals
    WHERE rotation_manifest_approvals.manifest_id = v_manifest_id;
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run_account_id, v_approver_id,
      CASE WHEN v_existing_decision = 'approved'
        THEN 'manifest_approved' ELSE 'manifest_rejected' END,
      CASE WHEN v_existing_decision = 'approved' THEN 'accepted' ELSE 'blocked' END,
      CASE WHEN v_existing_decision = 'approved' THEN 'none'
        ELSE 'approval_required' END
    );
    RETURN QUERY SELECT
      'already_recorded'::TEXT, 'none'::TEXT, v_manifest_id;
    RETURN;
  END IF;

  IF p_decision = 'approved' AND EXISTS (
    SELECT 1
    FROM public.rotation_manifest_entries
    WHERE rotation_manifest_entries.manifest_id = v_manifest_id
      AND legacy_owner = 'unknown'
  ) THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run_account_id, v_approver_id,
      'manifest_rejected', 'blocked', 'unknown_ownership'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, 'unknown_ownership'::TEXT, v_manifest_id;
    RETURN;
  END IF;

  IF p_decision = 'approved' AND EXISTS (
    SELECT 1
    FROM public.rotation_manifest_entries e
    WHERE e.manifest_id = v_manifest_id
      AND NOT public.rotation_manifest_entry_digest_matches(e)
  ) THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run_account_id, v_approver_id,
      'manifest_rejected', 'blocked', 'digest_mismatch'
    );
    RETURN QUERY SELECT
      'rejected'::TEXT, 'digest_mismatch'::TEXT, v_manifest_id;
    RETURN;
  END IF;

  INSERT INTO public.rotation_manifest_approvals (
    manifest_id, run_id, manifest_digest, decision, approver_id
  ) VALUES (
    v_manifest_id, p_run_id, v_stored_digest, p_decision, v_approver_id
  );

  UPDATE public.rotation_runs
  SET status = CASE WHEN p_decision = 'approved' THEN 'approved' ELSE 'blocked' END,
      reason_code = CASE WHEN p_decision = 'approved' THEN 'none'
        ELSE 'approval_required' END
  WHERE id = p_run_id;

  INSERT INTO public.rotation_audit_events (
    run_id, account_id, actor_id, event_type, status, reason_code
  ) VALUES (
    p_run_id,
    v_run_account_id,
    v_approver_id,
    CASE WHEN p_decision = 'approved'
      THEN 'manifest_approved' ELSE 'manifest_rejected' END,
    CASE WHEN p_decision = 'approved' THEN 'accepted' ELSE 'blocked' END,
    CASE WHEN p_decision = 'approved' THEN 'none' ELSE 'approval_required' END
  );

  RETURN QUERY SELECT
    p_decision,
    CASE WHEN p_decision = 'approved' THEN 'none' ELSE 'approval_required' END,
    v_manifest_id;
END;
$$;

-- ============================================================
-- Executable lifecycle, accounting, retirement, purge, monitoring
-- ============================================================
CREATE FUNCTION public.enable_key_rotation_operations()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '8s'
SET statement_timeout = '30s'
AS $$
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;

  PERFORM public.lock_key_rotation_control();
  UPDATE public.rotation_runtime_control
  SET operations_enabled = TRUE,
      disabled_reason = 'enabled',
      updated_by = auth.uid(),
      updated_at = now()
  WHERE singleton;

  INSERT INTO public.rotation_audit_events (
    actor_id, event_type, status, reason_code
  ) VALUES (
    auth.uid(), 'operations_enabled', 'accepted', 'none'
  );
END;
$$;

CREATE FUNCTION public.prepare_key_rotation_run(
  p_account_id UUID,
  p_mode TEXT,
  p_current_key_fingerprint UUID,
  p_previous_key_fingerprint UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '8s'
SET statement_timeout = '30s'
AS $$
DECLARE
  v_run_id UUID;
  v_expected_items BIGINT;
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;
  IF p_mode NOT IN ('dry_run', 'apply', 'final_audit') THEN
    RAISE EXCEPTION 'invalid rotation mode' USING ERRCODE = '22023';
  END IF;

  PERFORM public.lock_key_rotation_control();
  PERFORM public.lock_key_rotation_account(p_account_id);

  INSERT INTO public.rotation_runs (
    account_id, mode, current_key_fingerprint, previous_key_fingerprint,
    operator_id
  ) VALUES (
    p_account_id, p_mode, p_current_key_fingerprint,
    p_previous_key_fingerprint, auth.uid()
  )
  RETURNING id INTO v_run_id;

  WITH numbered AS (
    SELECT
      inventory.*,
      row_number() OVER (
        ORDER BY inventory.table_name, inventory.row_id
      )::BIGINT AS sequence
    FROM public.key_rotation_inventory(p_account_id) AS inventory
  )
  INSERT INTO public.rotation_items (
    run_id, sequence, account_id, table_name, row_id, target_paths,
    expected_version, expected_fingerprint
  )
  SELECT
    v_run_id, numbered.sequence, numbered.account_id, numbered.table_name,
    numbered.row_id, numbered.target_paths, numbered.secret_version,
    numbered.secret_fingerprint
  FROM numbered;

  GET DIAGNOSTICS v_expected_items = ROW_COUNT;
  UPDATE public.rotation_runs
  SET expected_items = v_expected_items
  WHERE id = v_run_id;

  INSERT INTO public.rotation_audit_events (
    run_id, account_id, actor_id, event_type, status, reason_code
  ) VALUES (
    v_run_id, p_account_id, auth.uid(), 'run_created', 'planned', 'created'
  );

  RETURN v_run_id;
END;
$$;

CREATE FUNCTION public.start_key_rotation_run(p_run_id UUID)
RETURNS TABLE (outcome TEXT, reason_code TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '8s'
SET statement_timeout = '30s'
AS $$
DECLARE
  v_enabled BOOLEAN;
  v_status TEXT;
  v_mode TEXT;
  v_expected_items BIGINT;
  v_account_id UUID;
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;

  PERFORM public.lock_key_rotation_control();
  IF NOT public.lock_key_rotation_run(p_run_id) THEN
    RETURN QUERY SELECT 'rejected'::TEXT, 'invalid_payload'::TEXT;
    RETURN;
  END IF;

  SELECT control.operations_enabled
  INTO v_enabled
  FROM public.rotation_runtime_control AS control
  WHERE control.singleton;
  SELECT run.status, run.mode, run.expected_items, run.account_id
  INTO v_status, v_mode, v_expected_items, v_account_id
  FROM public.rotation_runs AS run
  WHERE run.id = p_run_id;

  IF v_status = 'running' THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_account_id, auth.uid(), 'run_started', 'accepted', 'started'
    );
    RETURN QUERY SELECT 'already_started'::TEXT, 'none'::TEXT;
    RETURN;
  END IF;
  IF v_mode = 'apply' AND NOT COALESCE(v_enabled, FALSE) THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_account_id, auth.uid(), 'run_started', 'blocked',
      'operations_disabled'
    );
    RETURN QUERY SELECT 'rejected'::TEXT, 'operations_disabled'::TEXT;
    RETURN;
  END IF;
  IF v_mode = 'dry_run' AND v_status = 'planned' THEN
    NULL;
  ELSIF v_mode IN ('dry_run', 'final_audit') AND
        v_expected_items = 0 AND v_status = 'planned' THEN
    NULL;
  ELSIF v_status <> 'approved' OR NOT EXISTS (
    SELECT 1
    FROM public.rotation_manifests AS manifest
    JOIN public.rotation_manifest_approvals AS approval
      ON approval.manifest_id = manifest.id
     AND approval.manifest_digest = manifest.manifest_digest
     AND approval.decision = 'approved'
    WHERE manifest.run_id = p_run_id
      AND manifest.revision = (
        SELECT MAX(latest.revision)
        FROM public.rotation_manifests AS latest
        WHERE latest.run_id = p_run_id
      )
  ) THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_account_id, auth.uid(), 'run_started', 'blocked',
      'approval_required'
    );
    RETURN QUERY SELECT 'rejected'::TEXT, 'approval_required'::TEXT;
    RETURN;
  END IF;

  UPDATE public.rotation_runs
  SET status = 'running',
      reason_code = CASE WHEN v_expected_items = 0
        THEN 'zero_inventory' ELSE 'started' END,
      started_at = COALESCE(started_at, now())
  WHERE id = p_run_id;
  INSERT INTO public.rotation_audit_events (
    run_id, account_id, actor_id, event_type, status, reason_code
  ) VALUES (
    p_run_id, v_account_id, auth.uid(), 'run_started', 'accepted',
    CASE WHEN v_expected_items = 0 THEN 'zero_inventory' ELSE 'started' END
  );
  RETURN QUERY SELECT 'started'::TEXT, 'none'::TEXT;
END;
$$;

CREATE FUNCTION public.finalize_key_rotation_run(p_run_id UUID)
RETURNS TABLE (outcome TEXT, reason_code TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '8s'
SET statement_timeout = '30s'
AS $$
DECLARE
  v_run public.rotation_runs%ROWTYPE;
  v_value_count BIGINT;
  v_inventory_count BIGINT;
  v_manifest_id UUID;
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;

  PERFORM public.lock_key_rotation_control();
  SELECT run.account_id INTO v_run.account_id
  FROM public.rotation_runs AS run WHERE run.id = p_run_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'rejected'::TEXT, 'invalid_payload'::TEXT;
    RETURN;
  END IF;
  PERFORM public.lock_key_rotation_account(v_run.account_id);
  IF NOT public.lock_key_rotation_run(p_run_id) THEN
    RETURN QUERY SELECT 'rejected'::TEXT, 'invalid_payload'::TEXT;
    RETURN;
  END IF;
  PERFORM public.refresh_key_rotation_accounting(p_run_id);

  SELECT * INTO v_run
  FROM public.rotation_runs
  WHERE id = p_run_id;

  IF v_run.status = 'completed' THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run.account_id, auth.uid(), 'run_completed', 'accepted',
      'completed'
    );
    RETURN QUERY SELECT 'already_completed'::TEXT, 'none'::TEXT;
    RETURN;
  END IF;

  IF v_run.status IS DISTINCT FROM 'running' THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run.account_id, auth.uid(), 'gate_failed', 'blocked',
      'count_mismatch'
    );
    RETURN QUERY SELECT 'blocked'::TEXT, 'count_mismatch'::TEXT;
    RETURN;
  END IF;

  SELECT COUNT(*)::BIGINT INTO v_inventory_count
  FROM public.key_rotation_inventory(v_run.account_id);

  -- Snapshot and actual inventory must be identical under the account barrier.
  IF v_inventory_count IS DISTINCT FROM v_run.expected_items OR
     EXISTS (
       SELECT 1
       FROM public.key_rotation_inventory(v_run.account_id) AS actual
       FULL JOIN (
         SELECT * FROM public.rotation_items WHERE run_id = p_run_id
       ) AS item
         ON item.table_name = actual.table_name
        AND item.row_id = actual.row_id
       WHERE item.id IS NULL OR actual.row_id IS NULL OR
         item.target_paths IS DISTINCT FROM actual.target_paths
     ) THEN
    UPDATE public.rotation_runs SET reason_code = 'inventory_changed'
    WHERE id = p_run_id;
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run.account_id, auth.uid(), 'gate_failed', 'blocked',
      'inventory_changed'
    );
    RETURN QUERY SELECT 'blocked'::TEXT, 'inventory_changed'::TEXT;
    RETURN;
  END IF;

  IF v_run.mode = 'apply' AND (
    v_run.expected_items <> v_run.visited_items OR
    v_run.expected_items <> v_run.terminal_items OR
    EXISTS (
      SELECT 1 FROM public.rotation_items AS item
      WHERE item.run_id = p_run_id AND (
        item.status <> 'applied' OR item.replacement_payload_digest IS NULL OR
        NOT public.rotation_item_matches_applied_metadata(item)
      )
    )
  ) THEN
    UPDATE public.rotation_runs SET reason_code = 'count_mismatch'
    WHERE id = p_run_id;
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run.account_id, auth.uid(), 'gate_failed', 'blocked',
      'count_mismatch'
    );
    RETURN QUERY SELECT 'blocked'::TEXT, 'count_mismatch'::TEXT;
    RETURN;
  END IF;

  IF v_run.mode IN ('dry_run', 'final_audit') AND EXISTS (
    SELECT 1
    FROM public.rotation_items AS item
    JOIN public.key_rotation_inventory(v_run.account_id) AS actual
      ON actual.table_name = item.table_name AND actual.row_id = item.row_id
    WHERE item.run_id = p_run_id AND (
      item.expected_version IS DISTINCT FROM actual.secret_version OR
      item.expected_fingerprint IS DISTINCT FROM actual.secret_fingerprint
    )
  ) THEN
    UPDATE public.rotation_runs SET reason_code = 'inventory_changed'
    WHERE id = p_run_id;
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run.account_id, auth.uid(), 'gate_failed', 'blocked',
      'inventory_changed'
    );
    RETURN QUERY SELECT 'blocked'::TEXT, 'inventory_changed'::TEXT;
    RETURN;
  END IF;

  IF v_run.mode = 'final_audit' AND v_run.expected_items > 0 THEN
    SELECT manifest.id INTO v_manifest_id
    FROM public.rotation_manifests AS manifest
    JOIN public.rotation_manifest_approvals AS approval
      ON approval.manifest_id = manifest.id
     AND approval.manifest_digest = manifest.manifest_digest
     AND approval.decision = 'approved'
    WHERE manifest.run_id = p_run_id
    ORDER BY manifest.revision DESC
    LIMIT 1;

    IF v_manifest_id IS NULL OR EXISTS (
      SELECT 1
      FROM public.rotation_manifest_entries AS entry
      WHERE entry.manifest_id = v_manifest_id AND (
        entry.value_format <> 'gcm' OR entry.legacy_owner <> 'current' OR
        NOT public.rotation_manifest_entry_digest_matches(entry)
      )
    ) OR (
      SELECT COUNT(*) FROM public.rotation_manifest_entries AS entry
      WHERE entry.manifest_id = v_manifest_id
    ) IS DISTINCT FROM (
      SELECT COALESCE(SUM(cardinality(actual.target_paths)), 0)
      FROM public.key_rotation_inventory(v_run.account_id) AS actual
    ) THEN
      UPDATE public.rotation_runs SET reason_code = 'gate_failed'
      WHERE id = p_run_id;
      INSERT INTO public.rotation_audit_events (
        run_id, account_id, actor_id, event_type, status, reason_code
      ) VALUES (
        p_run_id, v_run.account_id, auth.uid(), 'gate_failed', 'blocked',
        'gate_failed'
      );
      RETURN QUERY SELECT 'blocked'::TEXT, 'gate_failed'::TEXT;
      RETURN;
    END IF;
  END IF;

  IF v_run.mode IN ('dry_run', 'final_audit') THEN
    UPDATE public.rotation_items
    SET status = 'validated', reason_code = 'none', attempts = 1,
        first_attempted_at = COALESCE(first_attempted_at, now()),
        terminal_at = now()
    WHERE run_id = p_run_id;
    UPDATE public.rotation_runs
    SET visited_items = expected_items, terminal_items = expected_items
    WHERE id = p_run_id;
  END IF;

  SELECT COALESCE(SUM(cardinality(item.target_paths)), 0)::BIGINT
  INTO v_value_count
  FROM public.rotation_items AS item
  WHERE item.run_id = p_run_id;

  UPDATE public.rotation_runs
  SET status = 'completed',
      reason_code = 'completed',
      completed_at = now(),
      current_values = v_value_count,
      previous_values = 0,
      unknown_values = 0,
      failed_values = 0
  WHERE id = p_run_id;
  INSERT INTO public.rotation_audit_events (
    run_id, account_id, actor_id, event_type, status, reason_code
  ) VALUES (
    p_run_id, v_run.account_id, auth.uid(), 'run_completed', 'completed',
    'completed'
  );
  RETURN QUERY SELECT 'completed'::TEXT, 'none'::TEXT;
END;
$$;

CREATE FUNCTION public.confirm_previous_key_retirement(p_run_id UUID)
RETURNS TABLE (
  outcome TEXT,
  previous_key_retired_at TIMESTAMPTZ,
  purge_after TIMESTAMPTZ,
  reason_code TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '8s'
SET statement_timeout = '30s'
AS $$
DECLARE
  v_enabled BOOLEAN;
  v_run public.rotation_runs%ROWTYPE;
  v_inventory_count BIGINT;
  v_manifest_id UUID;
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;

  PERFORM public.lock_key_rotation_control();
  SELECT run.account_id INTO v_run.account_id
  FROM public.rotation_runs AS run WHERE run.id = p_run_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT
      'rejected'::TEXT, NULL::TIMESTAMPTZ, NULL::TIMESTAMPTZ,
      'invalid_payload'::TEXT;
    RETURN;
  END IF;
  PERFORM public.lock_key_rotation_account(v_run.account_id);
  IF NOT public.lock_key_rotation_run(p_run_id) THEN
    RETURN QUERY SELECT
      'rejected'::TEXT, NULL::TIMESTAMPTZ, NULL::TIMESTAMPTZ,
      'invalid_payload'::TEXT;
    RETURN;
  END IF;
  SELECT operations_enabled INTO v_enabled
  FROM public.rotation_runtime_control WHERE singleton;
  SELECT * INTO v_run FROM public.rotation_runs WHERE id = p_run_id;

  IF v_run.previous_key_retired_at IS NOT NULL THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run.account_id, auth.uid(), 'key_retired', 'accepted', 'none'
    );
    RETURN QUERY SELECT
      'already_retired'::TEXT, v_run.previous_key_retired_at,
      v_run.purge_after, 'none'::TEXT;
    RETURN;
  END IF;

  SELECT COUNT(*)::BIGINT INTO v_inventory_count
  FROM public.key_rotation_inventory(v_run.account_id);
  SELECT manifest.id INTO v_manifest_id
  FROM public.rotation_manifests AS manifest
  JOIN public.rotation_manifest_approvals AS approval
    ON approval.manifest_id = manifest.id
   AND approval.manifest_digest = manifest.manifest_digest
   AND approval.decision = 'approved'
  WHERE manifest.run_id = p_run_id
  ORDER BY manifest.revision DESC
  LIMIT 1;

  IF COALESCE(v_enabled, FALSE) OR
     v_run.mode <> 'final_audit' OR
     v_run.status <> 'completed' OR
     v_inventory_count IS DISTINCT FROM v_run.expected_items OR
     EXISTS (
       SELECT 1
       FROM public.key_rotation_inventory(v_run.account_id) AS actual
       FULL JOIN (
         SELECT * FROM public.rotation_items WHERE run_id = p_run_id
       ) AS item
         ON item.table_name = actual.table_name
        AND item.row_id = actual.row_id
       WHERE item.id IS NULL OR actual.row_id IS NULL OR
         item.target_paths IS DISTINCT FROM actual.target_paths OR
         item.expected_version IS DISTINCT FROM actual.secret_version OR
         item.expected_fingerprint IS DISTINCT FROM actual.secret_fingerprint
     ) OR
     (v_run.expected_items > 0 AND (
       v_manifest_id IS NULL OR EXISTS (
         SELECT 1 FROM public.rotation_manifest_entries AS entry
         WHERE entry.manifest_id = v_manifest_id AND (
           entry.value_format <> 'gcm' OR entry.legacy_owner <> 'current' OR
           NOT public.rotation_manifest_entry_digest_matches(entry)
         )
       )
     )) OR
     v_run.expected_items <> v_run.terminal_items OR
     v_run.failed_values <> 0 OR
     v_run.previous_values <> 0 OR
     v_run.unknown_values <> 0 THEN
    UPDATE public.rotation_runs SET reason_code = 'gate_failed'
    WHERE id = p_run_id;
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run.account_id, auth.uid(), 'gate_failed', 'blocked',
      'gate_failed'
    );
    RETURN QUERY SELECT
      'blocked'::TEXT, NULL::TIMESTAMPTZ, NULL::TIMESTAMPTZ,
      'gate_failed'::TEXT;
    RETURN;
  END IF;

  UPDATE public.rotation_runs
  SET status = 'retired',
      previous_key_retired_at = now(),
      purge_after = now() + INTERVAL '90 days'
  WHERE id = p_run_id
  RETURNING rotation_runs.previous_key_retired_at,
    rotation_runs.purge_after
  INTO v_run.previous_key_retired_at, v_run.purge_after;

  INSERT INTO public.rotation_audit_events (
    run_id, account_id, actor_id, event_type, status, reason_code
  ) VALUES (
    p_run_id, v_run.account_id, auth.uid(), 'key_retired', 'accepted', 'none'
  );
  RETURN QUERY SELECT
    'retired'::TEXT, v_run.previous_key_retired_at, v_run.purge_after,
    'none'::TEXT;
END;
$$;

CREATE FUNCTION public.purge_rotation_evidence(p_run_id UUID)
RETURNS TABLE (outcome TEXT, reason_code TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '8s'
SET statement_timeout = '30s'
AS $$
DECLARE
  v_enabled BOOLEAN;
  v_run public.rotation_runs%ROWTYPE;
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;

  PERFORM public.lock_key_rotation_control();
  IF NOT public.lock_key_rotation_run(p_run_id) THEN
    RETURN QUERY SELECT 'rejected'::TEXT, 'invalid_payload'::TEXT;
    RETURN;
  END IF;
  SELECT operations_enabled INTO v_enabled
  FROM public.rotation_runtime_control WHERE singleton;
  SELECT * INTO v_run FROM public.rotation_runs WHERE id = p_run_id;

  IF NOT EXISTS (
    SELECT 1 FROM public.rotation_manifests WHERE run_id = p_run_id
  ) THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run.account_id, auth.uid(), 'manifest_purged', 'accepted',
      'already_purged'
    );
    RETURN QUERY SELECT 'already_purged'::TEXT, 'already_purged'::TEXT;
    RETURN;
  END IF;
  IF COALESCE(v_enabled, FALSE) OR v_run.status <> 'retired' OR
     v_run.purge_after IS NULL OR now() < v_run.purge_after THEN
    INSERT INTO public.rotation_audit_events (
      run_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, v_run.account_id, auth.uid(), 'gate_failed', 'blocked',
      'retention_active'
    );
    RETURN QUERY SELECT 'blocked'::TEXT, 'retention_active'::TEXT;
    RETURN;
  END IF;

  PERFORM set_config('app.key_rotation_purge', 'authorized', TRUE);
  UPDATE public.rotation_audit_events
  SET item_id = NULL
  WHERE run_id = p_run_id AND item_id IS NOT NULL;
  DELETE FROM public.rotation_manifest_approvals WHERE run_id = p_run_id;
  DELETE FROM public.rotation_manifest_entries WHERE run_id = p_run_id;
  DELETE FROM public.rotation_manifests WHERE run_id = p_run_id;
  DELETE FROM public.rotation_items WHERE run_id = p_run_id;

  INSERT INTO public.rotation_audit_events (
    run_id, account_id, actor_id, event_type, status, reason_code
  ) VALUES (
    p_run_id, v_run.account_id, auth.uid(), 'manifest_purged', 'completed',
    'none'
  );
  RETURN QUERY SELECT 'purged'::TEXT, 'none'::TEXT;
END;
$$;

CREATE FUNCTION public.get_key_rotation_status(p_run_id UUID)
RETURNS TABLE (
  run_id UUID,
  account_id UUID,
  mode TEXT,
  status TEXT,
  reason_code TEXT,
  expected_items BIGINT,
  visited_items BIGINT,
  terminal_items BIGINT,
  applied_values BIGINT,
  current_values BIGINT,
  previous_values BIGINT,
  unknown_values BIGINT,
  failed_values BIGINT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  previous_key_retired_at TIMESTAMPTZ,
  purge_after TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT
    run.id, run.account_id, run.mode, run.status, run.reason_code,
    run.expected_items, run.visited_items, run.terminal_items,
    run.applied_values, run.current_values, run.previous_values,
    run.unknown_values, run.failed_values, run.started_at, run.completed_at,
    run.previous_key_retired_at, run.purge_after
  FROM public.rotation_runs AS run
  WHERE run.id = p_run_id;
END;
$$;

CREATE FUNCTION public.list_active_key_rotation_runs(
  p_stuck_after INTERVAL DEFAULT INTERVAL '15 minutes'
)
RETURNS TABLE (
  run_id UUID,
  account_id UUID,
  mode TEXT,
  status TEXT,
  reason_code TEXT,
  lifecycle_age_seconds BIGINT,
  is_stuck BOOLEAN,
  expected_items BIGINT,
  terminal_items BIGINT,
  error_count BIGINT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;
  IF p_stuck_after <= INTERVAL '0 seconds' THEN
    RAISE EXCEPTION 'stuck threshold must be positive' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT
    run.id,
    run.account_id,
    run.mode,
    run.status,
    run.reason_code,
    EXTRACT(EPOCH FROM (now() - COALESCE(run.started_at, run.created_at)))::BIGINT,
    now() - COALESCE(run.started_at, run.created_at) >= p_stuck_after,
    run.expected_items,
    run.terminal_items,
    run.failed_values
  FROM public.rotation_runs AS run
  WHERE run.status IN (
    'planned', 'awaiting_approval', 'approved', 'running', 'blocked'
  )
  ORDER BY run.created_at;
END;
$$;

CREATE FUNCTION public.get_key_rotation_audit_summary(p_run_id UUID)
RETURNS TABLE (
  run_id UUID,
  total_events BIGINT,
  error_events BIGINT,
  error_rate NUMERIC,
  lifecycle_age_seconds BIGINT,
  last_event_at TIMESTAMPTZ,
  waiting_advisory_locks BIGINT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF auth.role() IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT
    run.id,
    COUNT(event.id)::BIGINT,
    COUNT(event.id) FILTER (
      WHERE event.status IN ('blocked', 'failed')
    )::BIGINT,
    CASE WHEN COUNT(event.id) = 0 THEN 0::NUMERIC ELSE
      ROUND(
        COUNT(event.id) FILTER (
          WHERE event.status IN ('blocked', 'failed')
        )::NUMERIC / COUNT(event.id)::NUMERIC,
        6
      )
    END AS error_rate,
    EXTRACT(EPOCH FROM (
      COALESCE(run.completed_at, now()) - COALESCE(run.started_at, run.created_at)
    ))::BIGINT,
    MAX(event.created_at),
    (
      SELECT COUNT(*)::BIGINT
      FROM pg_catalog.pg_locks AS lock
      WHERE lock.locktype = 'advisory' AND NOT lock.granted
    )
  FROM public.rotation_runs AS run
  LEFT JOIN public.rotation_audit_events AS event ON event.run_id = run.id
  WHERE run.id = p_run_id
  GROUP BY run.id;
END;
$$;

CREATE FUNCTION public.reject_rotation_evidence_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF current_setting('app.key_rotation_purge', TRUE) IS DISTINCT FROM 'authorized' THEN
    RAISE EXCEPTION 'rotation evidence is immutable' USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER rotation_manifests_immutable
  BEFORE UPDATE OR DELETE ON rotation_manifests
  FOR EACH ROW EXECUTE FUNCTION public.reject_rotation_evidence_mutation();
CREATE TRIGGER rotation_manifest_entries_immutable
  BEFORE UPDATE OR DELETE ON rotation_manifest_entries
  FOR EACH ROW EXECUTE FUNCTION public.reject_rotation_evidence_mutation();
CREATE TRIGGER rotation_manifest_approvals_immutable
  BEFORE UPDATE OR DELETE ON rotation_manifest_approvals
  FOR EACH ROW EXECUTE FUNCTION public.reject_rotation_evidence_mutation();
CREATE TRIGGER rotation_audit_events_immutable
  BEFORE UPDATE OR DELETE ON rotation_audit_events
  FOR EACH ROW EXECUTE FUNCTION public.reject_rotation_evidence_mutation();

ALTER FUNCTION public.enable_key_rotation_operations()
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.prepare_key_rotation_run(UUID, TEXT, UUID, UUID)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.start_key_rotation_run(UUID)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.finalize_key_rotation_run(UUID)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.confirm_previous_key_retirement(UUID)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.purge_rotation_evidence(UUID)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.get_key_rotation_status(UUID)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.list_active_key_rotation_runs(INTERVAL)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.get_key_rotation_audit_summary(UUID)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.import_rotation_manifest(UUID, TEXT, JSONB)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.approve_rotation_manifest(UUID, TEXT, TEXT)
  OWNER TO key_rotation_executor;
ALTER FUNCTION public.reject_rotation_evidence_mutation()
  OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION public.import_rotation_manifest(UUID, TEXT, JSONB)
  FROM PUBLIC, anon, service_role;
REVOKE ALL ON FUNCTION public.approve_rotation_manifest(UUID, TEXT, TEXT)
  FROM PUBLIC, anon, service_role;
REVOKE ALL ON FUNCTION public.reject_rotation_evidence_mutation()
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.import_rotation_manifest(UUID, TEXT, JSONB)
  TO authenticated;
GRANT EXECUTE ON FUNCTION public.approve_rotation_manifest(UUID, TEXT, TEXT)
  TO authenticated;

REVOKE ALL ON FUNCTION public.enable_key_rotation_operations()
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.prepare_key_rotation_run(UUID, TEXT, UUID, UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.start_key_rotation_run(UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.finalize_key_rotation_run(UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.confirm_previous_key_retirement(UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.purge_rotation_evidence(UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.get_key_rotation_status(UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.list_active_key_rotation_runs(INTERVAL)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.get_key_rotation_audit_summary(UUID)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.enable_key_rotation_operations()
  TO service_role;
GRANT EXECUTE ON FUNCTION public.prepare_key_rotation_run(UUID, TEXT, UUID, UUID)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.start_key_rotation_run(UUID)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.finalize_key_rotation_run(UUID)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.confirm_previous_key_retirement(UUID)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.purge_rotation_evidence(UUID)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.get_key_rotation_status(UUID)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.list_active_key_rotation_runs(INTERVAL)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.get_key_rotation_audit_summary(UUID)
  TO service_role;
