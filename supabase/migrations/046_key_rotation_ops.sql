-- ============================================================
-- 046_key_rotation_ops.sql — confidential key-rotation contract
-- ============================================================
-- Expand-only. Production rollback is disable/revoke/fix-forward. This
-- migration intentionally contains no destructive DOWN section.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'key_rotation_executor') THEN
    CREATE ROLE key_rotation_executor NOLOGIN BYPASSRLS;
  END IF;
END
$$;

-- Encrypted-row metadata. Fingerprints are random opaque concurrency tokens;
-- they are never derived from plaintext or ciphertext.
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

CREATE FUNCTION bump_key_rotation_secret_metadata()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
  encrypted_value_changed BOOLEAN;
BEGIN
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
    NEW.secret_version := OLD.secret_version + 1;
    NEW.secret_fingerprint := gen_random_uuid();
  ELSE
    NEW.secret_version := OLD.secret_version;
    NEW.secret_fingerprint := OLD.secret_fingerprint;
  END IF;
  RETURN NEW;
END;
$$;

ALTER FUNCTION bump_key_rotation_secret_metadata() OWNER TO key_rotation_executor;

CREATE TRIGGER whatsapp_config_secret_metadata
  BEFORE UPDATE ON whatsapp_config
  FOR EACH ROW EXECUTE FUNCTION bump_key_rotation_secret_metadata();
CREATE TRIGGER salesforce_config_secret_metadata
  BEFORE UPDATE ON salesforce_config
  FOR EACH ROW EXECUTE FUNCTION bump_key_rotation_secret_metadata();
CREATE TRIGGER ai_configs_secret_metadata
  BEFORE UPDATE ON ai_configs
  FOR EACH ROW EXECUTE FUNCTION bump_key_rotation_secret_metadata();
CREATE TRIGGER webhook_endpoints_secret_metadata
  BEFORE UPDATE ON webhook_endpoints
  FOR EACH ROW EXECUTE FUNCTION bump_key_rotation_secret_metadata();

CREATE TABLE rotation_runtime_control (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  operations_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  disabled_reason TEXT NOT NULL DEFAULT 'not_enabled'
    CONSTRAINT rotation_runtime_reason_check CHECK (
      disabled_reason IN (
        'not_enabled', 'operator_disabled', 'incident_response',
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
  mode TEXT NOT NULL
    CONSTRAINT rotation_run_mode_check CHECK (mode IN ('dry_run', 'apply', 'final_audit')),
  status TEXT NOT NULL DEFAULT 'planned'
    CONSTRAINT rotation_run_status_check CHECK (
      status IN (
        'planned', 'awaiting_approval', 'approved', 'running', 'completed',
        'blocked', 'failed', 'retired'
      )
    ),
  reason_code TEXT NOT NULL DEFAULT 'created'
    CONSTRAINT rotation_reason_code_check CHECK (
      reason_code IN (
        'created', 'manifest_pending', 'manifest_reimported',
        'approval_required', 'digest_mismatch', 'role_collision',
        'unknown_ownership', 'invalid_payload', 'conflict', 'missing',
        'completed', 'gate_failed', 'retention_active', 'operator_disabled',
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
  )
);

CREATE TABLE rotation_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL REFERENCES rotation_runs(id) ON DELETE RESTRICT,
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
        'missing', 'failed', 'blocked'
      )
    ),
  reason_code TEXT NOT NULL DEFAULT 'none'
    CONSTRAINT rotation_item_reason_check CHECK (
      reason_code IN (
        'none', 'applied', 'already_applied', 'version_conflict',
        'row_missing', 'invalid_payload', 'approval_required',
        'unknown_ownership', 'digest_mismatch', 'role_collision',
        'operations_disabled'
      )
    ),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  applied_version BIGINT CHECK (applied_version >= 0),
  applied_fingerprint UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  first_attempted_at TIMESTAMPTZ,
  terminal_at TIMESTAMPTZ,
  UNIQUE (run_id, id),
  UNIQUE (run_id, table_name, row_id),
  UNIQUE (run_id, sequence),
  CONSTRAINT rotation_item_paths_allowed CHECK (
    CASE table_name
      WHEN 'whatsapp_config' THEN target_paths <@ ARRAY[
        'access_token', 'verify_token', 'provider_config.apiKey',
        'provider_config.secret'
      ]::TEXT[]
      WHEN 'salesforce_config' THEN target_paths <@ ARRAY[
        'client_id', 'client_secret', 'username', 'password',
        'security_token', 'webhook_secret'
      ]::TEXT[]
      WHEN 'ai_configs' THEN target_paths <@ ARRAY[
        'api_key', 'embeddings_api_key'
      ]::TEXT[]
      WHEN 'webhook_endpoints' THEN target_paths <@ ARRAY['secret']::TEXT[]
      ELSE FALSE
    END
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
    CASE table_name
      WHEN 'whatsapp_config' THEN value_path IN (
        'access_token', 'verify_token', 'provider_config.apiKey',
        'provider_config.secret'
      )
      WHEN 'salesforce_config' THEN value_path IN (
        'client_id', 'client_secret', 'username', 'password',
        'security_token', 'webhook_secret'
      )
      WHEN 'ai_configs' THEN value_path IN ('api_key', 'embeddings_api_key')
      WHEN 'webhook_endpoints' THEN value_path = 'secret'
      ELSE FALSE
    END
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
        'operations_enabled', 'operations_disabled', 'run_created',
        'manifest_imported', 'manifest_approved', 'manifest_rejected',
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
        'none', 'created', 'applied', 'already_applied',
        'version_conflict', 'row_missing', 'invalid_payload',
        'approval_required', 'unknown_ownership', 'digest_mismatch',
        'role_collision', 'operations_disabled', 'operator_disabled',
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
GRANT SELECT, INSERT ON rotation_manifests, rotation_manifest_entries,
  rotation_manifest_approvals, rotation_audit_events TO key_rotation_executor;
GRANT SELECT, UPDATE ON whatsapp_config, salesforce_config, ai_configs,
  webhook_endpoints TO key_rotation_executor;
GRANT SELECT ON profiles TO key_rotation_executor;

CREATE FUNCTION disable_key_rotation_operations(p_reason TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF auth.role() <> 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;
  IF p_reason NOT IN (
    'operator_disabled', 'incident_response', 'maintenance', 'fix_forward'
  ) THEN
    RAISE EXCEPTION 'invalid key rotation reason' USING ERRCODE = '22023';
  END IF;

  UPDATE rotation_runtime_control
  SET operations_enabled = FALSE,
      disabled_reason = p_reason,
      updated_by = auth.uid(),
      updated_at = now()
  WHERE singleton;

  INSERT INTO rotation_audit_events (
    actor_id, event_type, status, reason_code
  ) VALUES (
    auth.uid(), 'operations_disabled', 'accepted', p_reason
  );
END;
$$;

CREATE FUNCTION assert_key_rotation_rollback_safe()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF auth.role() <> 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;
  IF (SELECT operations_enabled FROM rotation_runtime_control WHERE singleton) THEN
    RAISE EXCEPTION 'key rotation must be disabled before rollback' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (SELECT 1 FROM rotation_runs) THEN
    RAISE EXCEPTION 'retained key rotation evidence blocks destructive rollback'
      USING ERRCODE = '55000';
  END IF;
END;
$$;

ALTER FUNCTION disable_key_rotation_operations(TEXT) OWNER TO key_rotation_executor;
ALTER FUNCTION assert_key_rotation_rollback_safe() OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION disable_key_rotation_operations(TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION assert_key_rotation_rollback_safe() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION disable_key_rotation_operations(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION assert_key_rotation_rollback_safe() TO service_role;

-- No DROP statements belong in this production migration. If a fix-forward
-- rollback is ever proposed, call assert_key_rotation_rollback_safe() first;
-- retained or active evidence deliberately blocks destructive reversal.

-- ============================================================
-- Task 4.2 — atomic, idempotent, service-role-only row rotation
-- ============================================================
CREATE FUNCTION rotate_encrypted_row(
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
SET search_path = public, pg_temp
AS $$
DECLARE
  v_operations_enabled BOOLEAN;
  v_run_status TEXT;
  v_item_status TEXT;
  v_item_table TEXT;
  v_item_row_id UUID;
  v_account_id UUID;
  v_expected_version BIGINT;
  v_expected_fingerprint UUID;
  v_target_paths TEXT[];
  v_payload_paths TEXT[];
  v_new_version BIGINT;
  v_new_fingerprint UUID;
  v_provider_config JSONB;
  v_row_exists BOOLEAN := FALSE;
BEGIN
  IF auth.role() <> 'service_role' THEN
    RAISE EXCEPTION 'key rotation authorization failed' USING ERRCODE = '42501';
  END IF;

  SELECT operations_enabled
  INTO v_operations_enabled
  FROM rotation_runtime_control
  WHERE singleton;

  SELECT
    r.status,
    i.status,
    i.table_name,
    i.row_id,
    i.account_id,
    i.expected_version,
    i.expected_fingerprint,
    i.target_paths
  INTO
    v_run_status,
    v_item_status,
    v_item_table,
    v_item_row_id,
    v_account_id,
    v_expected_version,
    v_expected_fingerprint,
    v_target_paths
  FROM rotation_items i
  JOIN rotation_runs r ON r.id = i.run_id
  WHERE i.run_id = p_run_id
    AND i.id = p_item_id
  FOR UPDATE OF i;

  IF NOT FOUND OR
     v_item_table IS DISTINCT FROM p_table OR
     v_item_row_id IS DISTINCT FROM p_row_id OR
     v_expected_version IS DISTINCT FROM p_expected_version OR
     v_expected_fingerprint IS DISTINCT FROM p_expected_fingerprint THEN
    RETURN QUERY SELECT
      'rejected'::TEXT, NULL::UUID, NULL::BIGINT, NULL::UUID,
      'invalid_payload'::TEXT;
    RETURN;
  END IF;

  IF v_item_status = 'applied' THEN
    INSERT INTO rotation_audit_events (
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
    FROM rotation_items i
    WHERE i.run_id = p_run_id AND i.id = p_item_id;
    RETURN;
  END IF;

  IF NOT COALESCE(v_operations_enabled, FALSE) THEN
    RETURN QUERY SELECT
      'rejected'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
      'operations_disabled'::TEXT;
    RETURN;
  END IF;

  IF v_run_status NOT IN ('approved', 'running') THEN
    RETURN QUERY SELECT
      'rejected'::TEXT, v_account_id, NULL::BIGINT, NULL::UUID,
      'approval_required'::TEXT;
    RETURN;
  END IF;

  IF jsonb_typeof(p_values) <> 'object' THEN
    RAISE EXCEPTION 'rotation payload must be an object' USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(key ORDER BY key)
  INTO v_payload_paths
  FROM jsonb_object_keys(p_values) AS keys(key);

  IF v_payload_paths IS DISTINCT FROM (
    SELECT array_agg(DISTINCT path ORDER BY path)
    FROM unnest(v_target_paths) AS paths(path)
  ) THEN
    RAISE EXCEPTION 'rotation payload keys do not match the manifest item'
      USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM jsonb_each(p_values) AS values_to_validate(path, encoded_value)
    WHERE jsonb_typeof(encoded_value) <> 'string'
       OR octet_length(encoded_value #>> '{}') > 16384
       OR encoded_value #>> '{}' !~ '^[0-9a-f]{24}:[0-9a-f]*:[0-9a-f]{32}$'
  ) THEN
    RAISE EXCEPTION 'rotation payload contains an invalid encrypted value'
      USING ERRCODE = '22023';
  END IF;

  -- Closed CASE p_table allow-list. No identifier or value is interpolated.
  CASE p_table
    WHEN 'whatsapp_config' THEN
      SELECT COALESCE(w.provider_config, '{}'::JSONB)
      INTO v_provider_config
      FROM whatsapp_config w
      WHERE w.id = p_row_id AND w.account_id = v_account_id;

      IF p_values ? 'provider_config.apiKey' THEN
        v_provider_config := jsonb_set(
          v_provider_config,
          '{apiKey}',
          to_jsonb(p_values ->> 'provider_config.apiKey'),
          TRUE
        );
      END IF;
      IF p_values ? 'provider_config.secret' THEN
        v_provider_config := jsonb_set(v_provider_config, '{secret}',
          to_jsonb(p_values ->> 'provider_config.secret'), TRUE);
      END IF;

      UPDATE whatsapp_config
      SET access_token = CASE
            WHEN p_values ? 'access_token' THEN p_values ->> 'access_token'
            ELSE access_token
          END,
          verify_token = CASE
            WHEN p_values ? 'verify_token' THEN p_values ->> 'verify_token'
            ELSE verify_token
          END,
          provider_config = v_provider_config
      WHERE id = p_row_id
        AND account_id = v_account_id
        AND secret_version = p_expected_version
        AND secret_fingerprint = p_expected_fingerprint
      RETURNING whatsapp_config.account_id, secret_version, secret_fingerprint
      INTO v_account_id, v_new_version, v_new_fingerprint;

    WHEN 'salesforce_config' THEN
      UPDATE salesforce_config
      SET client_id = CASE WHEN p_values ? 'client_id'
            THEN p_values ->> 'client_id' ELSE client_id END,
          client_secret = CASE WHEN p_values ? 'client_secret'
            THEN p_values ->> 'client_secret' ELSE client_secret END,
          username = CASE WHEN p_values ? 'username'
            THEN p_values ->> 'username' ELSE username END,
          password = CASE WHEN p_values ? 'password'
            THEN p_values ->> 'password' ELSE password END,
          security_token = CASE WHEN p_values ? 'security_token'
            THEN p_values ->> 'security_token' ELSE security_token END,
          webhook_secret = CASE WHEN p_values ? 'webhook_secret'
            THEN p_values ->> 'webhook_secret' ELSE webhook_secret END
      WHERE id = p_row_id
        AND account_id = v_account_id
        AND secret_version = p_expected_version
        AND secret_fingerprint = p_expected_fingerprint
      RETURNING salesforce_config.account_id, secret_version, secret_fingerprint
      INTO v_account_id, v_new_version, v_new_fingerprint;

    WHEN 'ai_configs' THEN
      UPDATE ai_configs
      SET api_key = CASE WHEN p_values ? 'api_key'
            THEN p_values ->> 'api_key' ELSE api_key END,
          embeddings_api_key = CASE WHEN p_values ? 'embeddings_api_key'
            THEN p_values ->> 'embeddings_api_key' ELSE embeddings_api_key END
      WHERE id = p_row_id
        AND account_id = v_account_id
        AND secret_version = p_expected_version
        AND secret_fingerprint = p_expected_fingerprint
      RETURNING ai_configs.account_id, secret_version, secret_fingerprint
      INTO v_account_id, v_new_version, v_new_fingerprint;

    WHEN 'webhook_endpoints' THEN
      UPDATE webhook_endpoints
      SET secret = p_values ->> 'secret'
      WHERE id = p_row_id
        AND account_id = v_account_id
        AND secret_version = p_expected_version
        AND secret_fingerprint = p_expected_fingerprint
      RETURNING webhook_endpoints.account_id, secret_version, secret_fingerprint
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
        SELECT EXISTS (SELECT 1 FROM whatsapp_config
          WHERE id = p_row_id AND account_id = v_account_id) INTO v_row_exists;
      WHEN 'salesforce_config' THEN
        SELECT EXISTS (SELECT 1 FROM salesforce_config
          WHERE id = p_row_id AND account_id = v_account_id) INTO v_row_exists;
      WHEN 'ai_configs' THEN
        SELECT EXISTS (SELECT 1 FROM ai_configs
          WHERE id = p_row_id AND account_id = v_account_id) INTO v_row_exists;
      WHEN 'webhook_endpoints' THEN
        SELECT EXISTS (SELECT 1 FROM webhook_endpoints
          WHERE id = p_row_id AND account_id = v_account_id) INTO v_row_exists;
      ELSE v_row_exists := FALSE;
    END CASE;

    UPDATE rotation_items
    SET status = CASE WHEN v_row_exists THEN 'conflict' ELSE 'missing' END,
        reason_code = CASE
          WHEN v_row_exists THEN 'version_conflict' ELSE 'row_missing'
        END,
        attempts = attempts + 1,
        first_attempted_at = COALESCE(first_attempted_at, now()),
        terminal_at = now()
    WHERE run_id = p_run_id AND id = p_item_id;

    INSERT INTO rotation_audit_events (
      run_id, item_id, account_id, actor_id, event_type, status, reason_code
    ) VALUES (
      p_run_id, p_item_id, v_account_id, auth.uid(),
      CASE WHEN v_row_exists THEN 'item_conflict' ELSE 'item_missing' END,
      'blocked',
      CASE WHEN v_row_exists THEN 'version_conflict' ELSE 'row_missing' END
    );

    RETURN QUERY SELECT
      CASE WHEN v_row_exists THEN 'conflict' ELSE 'missing' END::TEXT,
      v_account_id,
      NULL::BIGINT,
      NULL::UUID,
      CASE WHEN v_row_exists THEN 'version_conflict' ELSE 'row_missing' END::TEXT;
    RETURN;
  END IF;

  UPDATE rotation_items
  SET status = 'applied',
      reason_code = 'applied',
      attempts = attempts + 1,
      first_attempted_at = COALESCE(first_attempted_at, now()),
      applied_version = v_new_version,
      applied_fingerprint = v_new_fingerprint,
      terminal_at = now()
  WHERE run_id = p_run_id AND id = p_item_id;

  INSERT INTO rotation_audit_events (
    run_id, item_id, account_id, actor_id, event_type, status, reason_code
  ) VALUES (
    p_run_id, p_item_id, v_account_id, auth.uid(),
    'item_applied', 'applied', 'applied'
  );

  RETURN QUERY SELECT
    'applied'::TEXT,
    v_account_id,
    v_new_version,
    v_new_fingerprint,
    'applied'::TEXT;
END;
$$;

ALTER FUNCTION rotate_encrypted_row(
  UUID, UUID, TEXT, UUID, BIGINT, UUID, JSONB
) OWNER TO key_rotation_executor;
REVOKE ALL ON FUNCTION rotate_encrypted_row(
  UUID, UUID, TEXT, UUID, BIGINT, UUID, JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION rotate_encrypted_row(
  UUID, UUID, TEXT, UUID, BIGINT, UUID, JSONB
) TO service_role;
