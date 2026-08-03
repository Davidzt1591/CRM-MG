-- Deterministic two-session tests for the key-rotation write barrier.
-- Synchronization observes PostgreSQL lock state with bounded polling; no test
-- infers blocking from a fixed sleep.
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS dblink WITH SCHEMA extensions;
SET search_path = public, extensions;
SET lock_timeout = '2s';
SET statement_timeout = '15s';

SELECT plan(10);

INSERT INTO auth.users (
  id, aud, role, email, encrypted_password, raw_app_meta_data,
  raw_user_meta_data, created_at, updated_at
) VALUES
  ('81000000-0000-0000-0000-000000000001', 'authenticated', 'authenticated',
   'concurrency-preparer@example.test', '', '{}'::jsonb, '{}'::jsonb, now(), now()),
  ('81000000-0000-0000-0000-000000000002', 'authenticated', 'authenticated',
   'concurrency-approver@example.test', '', '{}'::jsonb, '{}'::jsonb, now(), now());

INSERT INTO accounts (id, name, owner_user_id) VALUES (
  '82000000-0000-0000-0000-000000000001',
  'Rotation concurrency account',
  '81000000-0000-0000-0000-000000000001'
);

INSERT INTO profiles (
  id, user_id, full_name, email, account_id, account_role
) VALUES
  ('83000000-0000-0000-0000-000000000001',
   '81000000-0000-0000-0000-000000000001', 'Concurrency Preparer',
   'concurrency-preparer@example.test',
   '82000000-0000-0000-0000-000000000001', 'owner'),
  ('83000000-0000-0000-0000-000000000002',
   '81000000-0000-0000-0000-000000000002', 'Concurrency Approver',
   'concurrency-approver@example.test',
   '82000000-0000-0000-0000-000000000001', 'admin');

INSERT INTO whatsapp_config (
  id, user_id, account_id, phone_number_id, access_token, provider_config
) VALUES (
  '84000000-0000-0000-0000-000000000001',
  '81000000-0000-0000-0000-000000000001',
  '82000000-0000-0000-0000-000000000001',
  'concurrency-phone',
  repeat('1', 24) || ':' || repeat('2', 32) || ':' || repeat('3', 32),
  jsonb_build_object(
    'apiKey', repeat('4', 24) || ':' || repeat('5', 32) || ':' || repeat('6', 32),
    'region', 'initial'
  )
);

SELECT extensions.dblink_connect(
  'kr_a', 'host=127.0.0.1 port=5432 dbname=postgres user=postgres password=postgres'
);
SELECT extensions.dblink_connect(
  'kr_b', 'host=127.0.0.1 port=5432 dbname=postgres user=postgres password=postgres'
);
SELECT extensions.dblink_exec('kr_a', $$SET lock_timeout = '5s'$$);
SELECT extensions.dblink_exec('kr_a', $$SET statement_timeout = '10s'$$);
SELECT extensions.dblink_exec('kr_b', $$SET lock_timeout = '5s'$$);
SELECT extensions.dblink_exec('kr_b', $$SET statement_timeout = '10s'$$);

CREATE TEMP TABLE kr_backend AS
SELECT 'a'::TEXT AS connection, pid
FROM extensions.dblink('kr_a', 'SELECT pg_backend_pid()') AS remote(pid INTEGER)
UNION ALL
SELECT 'b'::TEXT, pid
FROM extensions.dblink('kr_b', 'SELECT pg_backend_pid()') AS remote(pid INTEGER);

CREATE FUNCTION pg_temp.wait_for_lock(p_pid INTEGER, p_timeout INTERVAL)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
  v_deadline TIMESTAMPTZ := clock_timestamp() + p_timeout;
BEGIN
  LOOP
    IF EXISTS (
      SELECT 1 FROM pg_catalog.pg_locks AS lock
      WHERE lock.pid = p_pid AND NOT lock.granted
    ) OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_stat_activity AS activity
      WHERE activity.pid = p_pid AND activity.wait_event_type = 'Lock'
    ) THEN
      RETURN TRUE;
    END IF;
    IF clock_timestamp() >= v_deadline THEN
      RETURN FALSE;
    END IF;
    PERFORM 1;
  END LOOP;
END;
$$;

CREATE FUNCTION pg_temp.wait_for_idle(p_connection TEXT, p_timeout INTERVAL)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
  v_deadline TIMESTAMPTZ := clock_timestamp() + p_timeout;
BEGIN
  LOOP
    IF extensions.dblink_is_busy(p_connection) = 0 THEN
      RETURN TRUE;
    END IF;
    IF clock_timestamp() >= v_deadline THEN
      RETURN FALSE;
    END IF;
    PERFORM 1;
  END LOOP;
END;
$$;

CREATE FUNCTION pg_temp.seed_public_run(p_mode TEXT)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
  v_run_id UUID;
  v_entries JSONB;
  v_digest TEXT;
BEGIN
  PERFORM set_config(
    'request.jwt.claims',
    '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}',
    TRUE
  );
  SELECT public.prepare_key_rotation_run(
    '82000000-0000-0000-0000-000000000001', p_mode,
    '86000000-0000-0000-0000-000000000001',
    '86000000-0000-0000-0000-000000000002'
  ) INTO v_run_id;

  IF p_mode <> 'dry_run' THEN
    SELECT jsonb_agg(
      jsonb_build_object(
        'account_id', item.account_id,
        'table_name', item.table_name,
        'row_id', item.row_id,
        'value_path', path.value_path,
        'value_format', 'gcm',
        'legacy_owner', 'current',
        'value_digest', encode(extensions.digest(convert_to(
          CASE path.value_path
            WHEN 'access_token' THEN config.access_token
            WHEN 'provider_config.apiKey' THEN config.provider_config ->> 'apiKey'
          END,
          'UTF8'
        ), 'sha256'), 'hex')
      ) ORDER BY item.table_name, item.row_id, path.value_path
    )
    INTO v_entries
    FROM public.rotation_items AS item
    CROSS JOIN LATERAL unnest(item.target_paths) AS path(value_path)
    JOIN public.whatsapp_config AS config ON config.id = item.row_id
    WHERE item.run_id = v_run_id;
    v_digest := encode(
      extensions.digest(convert_to(v_entries::TEXT, 'UTF8'), 'sha256'), 'hex'
    );

    PERFORM set_config(
      'request.jwt.claims',
      '{"role":"authenticated","sub":"81000000-0000-0000-0000-000000000001"}',
      TRUE
    );
    PERFORM * FROM public.import_rotation_manifest(v_run_id, v_digest, v_entries);
    PERFORM set_config(
      'request.jwt.claims',
      '{"role":"authenticated","sub":"81000000-0000-0000-0000-000000000002"}',
      TRUE
    );
    PERFORM * FROM public.approve_rotation_manifest(v_run_id, v_digest, 'approved');
  END IF;

  PERFORM set_config(
    'request.jwt.claims',
    '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}',
    TRUE
  );
  PERFORM * FROM public.start_key_rotation_run(v_run_id);
  RETURN v_run_id;
END;
$$;

SELECT set_config(
  'request.jwt.claims',
  '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}',
  TRUE
);
SELECT public.enable_key_rotation_operations();

-- emergency-disable-vs-rotate: rotate owns control/account/run/item/row locks;
-- emergency disable waits and then commits the disabled state.
CREATE TEMP TABLE emergency_run AS
SELECT pg_temp.seed_public_run('apply') AS run_id;
SELECT extensions.dblink_exec('kr_a', 'BEGIN');
SELECT extensions.dblink_send_query('kr_a', format(
  $$WITH claims AS MATERIALIZED (
      SELECT set_config('request.jwt.claims',
        '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}', FALSE)
    )
    SELECT rotation.* FROM claims
    CROSS JOIN LATERAL public.rotate_encrypted_row(
      %L,
      (SELECT id FROM public.rotation_items WHERE run_id = %L LIMIT 1),
      'whatsapp_config', '84000000-0000-0000-0000-000000000001',
      (SELECT expected_version FROM public.rotation_items WHERE run_id = %L LIMIT 1),
      (SELECT expected_fingerprint FROM public.rotation_items WHERE run_id = %L LIMIT 1),
      jsonb_build_object(
        'access_token', repeat('a', 24) || ':' || repeat('b', 32) || ':' || repeat('c', 32),
        'provider_config.apiKey', repeat('d', 24) || ':' || repeat('e', 32) || ':' || repeat('f', 32)
      )
    ) AS rotation WHERE claims.set_config IS NOT NULL$$,
  (SELECT run_id FROM emergency_run), (SELECT run_id FROM emergency_run),
  (SELECT run_id FROM emergency_run), (SELECT run_id FROM emergency_run)
));
CREATE TEMP TABLE emergency_rotate_result AS
SELECT * FROM extensions.dblink_get_result('kr_a') AS result(
  outcome TEXT, account_id UUID, new_version BIGINT,
  new_fingerprint UUID, reason_code TEXT
);
SELECT extensions.dblink_send_query(
  'kr_b',
  $$WITH claims AS MATERIALIZED (
      SELECT set_config('request.jwt.claims',
        '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}', FALSE)
    )
    SELECT public.disable_key_rotation_operations('incident_response')
    FROM claims WHERE claims.set_config IS NOT NULL$$
);
SELECT ok(
  pg_temp.wait_for_lock(
    (SELECT pid FROM kr_backend WHERE connection = 'b'), INTERVAL '2 seconds'
  ),
  'emergency-disable-vs-rotate exposes a real lock wait'
);
SELECT extensions.dblink_exec('kr_a', 'COMMIT');
SELECT * FROM extensions.dblink_get_result('kr_b') AS result(disabled TEXT);
SELECT is(
  (SELECT operations_enabled FROM rotation_runtime_control WHERE singleton),
  FALSE,
  'emergency-disable-vs-rotate leaves operations disabled'
);

-- inventory-vs-insert: prepare holds the account barrier through commit, so a
-- concurrent encrypted insert waits and finalization detects the new inventory.
SELECT extensions.dblink_exec('kr_a', 'BEGIN');
SELECT extensions.dblink_send_query(
  'kr_a',
  $$WITH claims AS MATERIALIZED (
      SELECT set_config('request.jwt.claims',
        '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}', FALSE)
    )
    SELECT public.prepare_key_rotation_run(
      '82000000-0000-0000-0000-000000000001', 'dry_run',
      '86000000-0000-0000-0000-000000000001', NULL
    ) FROM claims WHERE claims.set_config IS NOT NULL$$
);
CREATE TEMP TABLE inventory_run AS
SELECT * FROM extensions.dblink_get_result('kr_a') AS result(run_id UUID);
SELECT extensions.dblink_send_query(
  'kr_b',
  $$INSERT INTO public.webhook_endpoints (
      id, account_id, url, secret, events, is_active
    ) VALUES (
      '84000000-0000-0000-0000-000000000002',
      '82000000-0000-0000-0000-000000000001', 'https://example.test/hook',
      repeat('7', 24) || ':' || repeat('8', 32) || ':' || repeat('9', 32),
      ARRAY['message.received'], TRUE
    ) RETURNING id$$
);
SELECT ok(
  pg_temp.wait_for_lock(
    (SELECT pid FROM kr_backend WHERE connection = 'b'), INTERVAL '2 seconds'
  ),
  'inventory-vs-insert blocks an encrypted insert on the account barrier'
);
SELECT extensions.dblink_exec('kr_a', 'COMMIT');
SELECT * FROM extensions.dblink_get_result('kr_b') AS result(id UUID);
SELECT set_config(
  'request.jwt.claims',
  '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}',
  TRUE
);
SELECT * FROM public.start_key_rotation_run((SELECT run_id FROM inventory_run));
SELECT is(
  (SELECT reason_code FROM public.finalize_key_rotation_run(
    (SELECT run_id FROM inventory_run)
  )),
  'inventory_changed',
  'inventory-vs-insert is reconciled rather than silently completed'
);
DELETE FROM webhook_endpoints WHERE id = '84000000-0000-0000-0000-000000000002';

-- finalize-vs-secret-write: finalization holds the account barrier to commit.
CREATE TEMP TABLE finalize_run AS
SELECT pg_temp.seed_public_run('dry_run') AS run_id;
SELECT extensions.dblink_exec('kr_a', 'BEGIN');
SELECT extensions.dblink_send_query('kr_a', format(
  $$WITH claims AS MATERIALIZED (
      SELECT set_config('request.jwt.claims',
        '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}', FALSE)
    )
    SELECT gate.* FROM claims
    CROSS JOIN LATERAL public.finalize_key_rotation_run(%L) AS gate
    WHERE claims.set_config IS NOT NULL$$,
  (SELECT run_id FROM finalize_run)
));
CREATE TEMP TABLE finalize_result AS
SELECT * FROM extensions.dblink_get_result('kr_a') AS result(
  outcome TEXT, reason_code TEXT
);
SELECT extensions.dblink_send_query('kr_b', $$UPDATE public.whatsapp_config
  SET access_token = repeat('0', 24) || ':' || repeat('1', 32) || ':' || repeat('2', 32)
  WHERE id = '84000000-0000-0000-0000-000000000001'
  RETURNING id$$);
SELECT ok(
  pg_temp.wait_for_lock(
    (SELECT pid FROM kr_backend WHERE connection = 'b'), INTERVAL '2 seconds'
  ),
  'finalize-vs-secret-write exposes the account barrier wait'
);
SELECT extensions.dblink_exec('kr_a', 'COMMIT');
SELECT * FROM extensions.dblink_get_result('kr_b') AS result(id UUID);
SELECT is(
  (SELECT outcome FROM finalize_result), 'completed',
  'finalize-vs-secret-write completes before the queued write commits'
);

-- retire-vs-secret-write: retirement repeats the current-only inventory check
-- while holding the same account barrier.
CREATE TEMP TABLE retire_run AS
SELECT pg_temp.seed_public_run('final_audit') AS run_id;
SELECT * FROM public.finalize_key_rotation_run((SELECT run_id FROM retire_run));
SELECT public.disable_key_rotation_operations('maintenance');
SELECT extensions.dblink_exec('kr_a', 'BEGIN');
SELECT extensions.dblink_send_query('kr_a', format(
  $$WITH claims AS MATERIALIZED (
      SELECT set_config('request.jwt.claims',
        '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}', FALSE)
    )
    SELECT gate.* FROM claims
    CROSS JOIN LATERAL public.confirm_previous_key_retirement(%L) AS gate
    WHERE claims.set_config IS NOT NULL$$,
  (SELECT run_id FROM retire_run)
));
CREATE TEMP TABLE retire_result AS
SELECT * FROM extensions.dblink_get_result('kr_a') AS result(
  outcome TEXT, previous_key_retired_at TIMESTAMPTZ,
  purge_after TIMESTAMPTZ, reason_code TEXT
);
SELECT extensions.dblink_send_query('kr_b', $$UPDATE public.whatsapp_config
  SET access_token = repeat('3', 24) || ':' || repeat('4', 32) || ':' || repeat('5', 32)
  WHERE id = '84000000-0000-0000-0000-000000000001'
  RETURNING id$$);
SELECT ok(
  pg_temp.wait_for_lock(
    (SELECT pid FROM kr_backend WHERE connection = 'b'), INTERVAL '2 seconds'
  ),
  'retire-vs-secret-write exposes the account barrier wait'
);
SELECT extensions.dblink_exec('kr_a', 'COMMIT');
SELECT * FROM extensions.dblink_get_result('kr_b') AS result(id UUID);
SELECT is(
  (SELECT outcome FROM retire_result), 'retired',
  'retire-vs-secret-write commits retirement before the queued write'
);

-- unrelated-jsonb-vs-rotate: a non-secret JSONB property does not acquire the
-- account barrier and remains safe while a gate holds it.
SELECT extensions.dblink_exec('kr_a', 'BEGIN');
SELECT extensions.dblink_exec(
  'kr_a',
  $$DO $block$ BEGIN
      PERFORM public.lock_key_rotation_account(
        '82000000-0000-0000-0000-000000000001'
      );
    END $block$$$
);
SELECT extensions.dblink_send_query('kr_b', $$UPDATE public.whatsapp_config
  SET provider_config = jsonb_set(provider_config, '{region}', '"concurrent"'::jsonb)
  WHERE id = '84000000-0000-0000-0000-000000000001'
  RETURNING id$$);
SELECT ok(
  pg_temp.wait_for_idle('kr_b', INTERVAL '2 seconds'),
  'unrelated-jsonb-vs-rotate does not wait on the secret barrier'
);
CREATE TEMP TABLE unrelated_result AS
SELECT * FROM extensions.dblink_get_result('kr_b') AS result(id UUID);
SELECT extensions.dblink_exec('kr_a', 'COMMIT');
SELECT is(
  (SELECT provider_config ->> 'region' FROM whatsapp_config
   WHERE id = '84000000-0000-0000-0000-000000000001'),
  'concurrent',
  'unrelated JSONB updates remain preserved'
);

SELECT extensions.dblink_disconnect('kr_a');
SELECT extensions.dblink_disconnect('kr_b');
SELECT set_config('app.key_rotation_purge', 'authorized', FALSE);
UPDATE rotation_audit_events SET item_id = NULL
WHERE account_id = '82000000-0000-0000-0000-000000000001';
DELETE FROM rotation_manifest_approvals WHERE run_id IN (
  SELECT id FROM rotation_runs WHERE account_id = '82000000-0000-0000-0000-000000000001'
);
DELETE FROM rotation_manifest_entries WHERE run_id IN (
  SELECT id FROM rotation_runs WHERE account_id = '82000000-0000-0000-0000-000000000001'
);
DELETE FROM rotation_manifests WHERE run_id IN (
  SELECT id FROM rotation_runs WHERE account_id = '82000000-0000-0000-0000-000000000001'
);
DELETE FROM rotation_items WHERE run_id IN (
  SELECT id FROM rotation_runs WHERE account_id = '82000000-0000-0000-0000-000000000001'
);
DELETE FROM rotation_audit_events
WHERE account_id = '82000000-0000-0000-0000-000000000001';
DELETE FROM rotation_runs
WHERE account_id = '82000000-0000-0000-0000-000000000001';
DELETE FROM whatsapp_config WHERE id = '84000000-0000-0000-0000-000000000001';
DELETE FROM profiles WHERE user_id::TEXT LIKE '81000000-%';
DELETE FROM accounts WHERE id = '82000000-0000-0000-0000-000000000001';
DELETE FROM auth.users WHERE id::TEXT LIKE '81000000-%';
SELECT set_config('app.key_rotation_purge', '', FALSE);
SELECT * FROM finish();
