-- Deterministic two-session tests for the key-rotation lock contract.
-- These tests use dblink connections to the same isolated local database.
CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS dblink WITH SCHEMA extensions;
SET search_path = public, extensions;

SELECT plan(11);

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

CREATE FUNCTION pg_temp.seed_authorized_run(
  p_run_id UUID,
  p_item_id UUID,
  p_target_paths TEXT[]
) RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
  v_manifest_id UUID;
  v_manifest_digest BYTEA := extensions.digest(
    convert_to(p_run_id::TEXT, 'UTF8'), 'sha256'
  );
BEGIN
  INSERT INTO rotation_runs (
    id, account_id, mode, status, reason_code, current_key_fingerprint,
    previous_key_fingerprint, expected_items, started_at
  ) VALUES (
    p_run_id, '82000000-0000-0000-0000-000000000001', 'apply', 'running',
    'started', '86000000-0000-0000-0000-000000000001',
    '86000000-0000-0000-0000-000000000002', 1, now()
  );

  INSERT INTO rotation_items (
    id, run_id, sequence, account_id, table_name, row_id, target_paths,
    expected_version, expected_fingerprint
  )
  SELECT
    p_item_id, p_run_id, 1,
    '82000000-0000-0000-0000-000000000001', 'whatsapp_config', id,
    p_target_paths, secret_version, secret_fingerprint
  FROM whatsapp_config
  WHERE id = '84000000-0000-0000-0000-000000000001';

  INSERT INTO rotation_manifests (
    run_id, revision, preparer_id, manifest_digest, entry_count
  ) VALUES (
    p_run_id, 1, '81000000-0000-0000-0000-000000000001',
    v_manifest_digest, cardinality(p_target_paths)
  ) RETURNING id INTO v_manifest_id;

  INSERT INTO rotation_manifest_entries (
    manifest_id, run_id, account_id, table_name, row_id, value_path,
    value_format, legacy_owner, value_digest
  )
  SELECT
    v_manifest_id, p_run_id,
    '82000000-0000-0000-0000-000000000001', 'whatsapp_config',
    '84000000-0000-0000-0000-000000000001', path, 'gcm', 'current',
    extensions.digest(convert_to(
      CASE path
        WHEN 'access_token' THEN config.access_token
        WHEN 'provider_config.apiKey' THEN config.provider_config ->> 'apiKey'
      END,
      'UTF8'
    ), 'sha256')
  FROM whatsapp_config AS config
  CROSS JOIN unnest(p_target_paths) AS paths(path)
  WHERE config.id = '84000000-0000-0000-0000-000000000001';

  INSERT INTO rotation_manifest_approvals (
    manifest_id, run_id, manifest_digest, decision, approver_id
  ) VALUES (
    v_manifest_id, p_run_id, v_manifest_digest, 'approved',
    '81000000-0000-0000-0000-000000000002'
  );
END;
$$;

SELECT pg_temp.seed_authorized_run(
  '85000000-0000-0000-0000-000000000001',
  '85000000-0000-0000-0000-000000000011',
  ARRAY['access_token']
);
UPDATE rotation_runtime_control
SET operations_enabled = TRUE, disabled_reason = 'maintenance'
WHERE singleton;

SELECT extensions.dblink_connect(
  'kr_a', 'host=127.0.0.1 port=5432 dbname=postgres user=postgres password=postgres'
);
SELECT extensions.dblink_connect(
  'kr_b', 'host=127.0.0.1 port=5432 dbname=postgres user=postgres password=postgres'
);

-- disable-vs-rotate: disable owns the control barrier before rotate starts.
SELECT extensions.dblink_exec('kr_a', 'BEGIN');
SELECT extensions.dblink_exec(
  'kr_a',
  'UPDATE public.rotation_runtime_control SET singleton = singleton WHERE singleton'
);
SELECT extensions.dblink_exec(
  'kr_a',
  $$UPDATE public.rotation_runtime_control
    SET operations_enabled = FALSE, disabled_reason = 'incident_response'
    WHERE singleton$$
);
SELECT extensions.dblink_send_query(
  'kr_b',
  $$WITH claims AS MATERIALIZED (
      SELECT set_config(
        'request.jwt.claims',
        '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}',
        FALSE
      )
    )
    SELECT rotation.*
    FROM claims
    CROSS JOIN LATERAL public.rotate_encrypted_row(
      '85000000-0000-0000-0000-000000000001',
      '85000000-0000-0000-0000-000000000011',
      'whatsapp_config',
      '84000000-0000-0000-0000-000000000001',
      0,
      (SELECT expected_fingerprint FROM public.rotation_items
       WHERE id = '85000000-0000-0000-0000-000000000011'),
      jsonb_build_object(
        'access_token', repeat('a', 24) || ':' || repeat('b', 32) || ':' || repeat('c', 32)
      )
    ) AS rotation
    WHERE claims.set_config IS NOT NULL$$
);
SELECT pg_sleep(0.2);
SELECT is(
  extensions.dblink_is_busy('kr_b'), 1,
  'disable-vs-rotate blocks the writer at the control barrier'
);
SELECT extensions.dblink_exec('kr_a', 'COMMIT');
CREATE TEMP TABLE disable_result AS
SELECT * FROM extensions.dblink_get_result('kr_b') AS result(
  outcome TEXT, account_id UUID, new_version BIGINT,
  new_fingerprint UUID, reason_code TEXT
);
SELECT is(
  (SELECT reason_code FROM disable_result),
  'operations_disabled',
  'disable-vs-rotate revalidates disabled mode before writing'
);
SELECT is(
  (SELECT secret_version FROM whatsapp_config
   WHERE id = '84000000-0000-0000-0000-000000000001'),
  0::BIGINT,
  'disable success prevents the queued rotation write'
);

-- reimport-vs-rotate: latest manifest revision wins under the run lock.
UPDATE rotation_runtime_control SET operations_enabled = TRUE WHERE singleton;
UPDATE rotation_items
SET status = 'planned', reason_code = 'none', attempts = 0, terminal_at = NULL
WHERE id = '85000000-0000-0000-0000-000000000011';
UPDATE rotation_runs
SET status = 'running', reason_code = 'started', visited_items = 0,
    terminal_items = 0, failed_values = 0
WHERE id = '85000000-0000-0000-0000-000000000001';
SELECT extensions.dblink_exec('kr_a', 'BEGIN');
SELECT extensions.dblink_exec(
  'kr_a',
  $$DO $block$
    BEGIN
      PERFORM set_config(
        'request.jwt.claims',
        '{"role":"authenticated","sub":"81000000-0000-0000-0000-000000000001"}',
        FALSE
      );
    END
  $block$$$
);
SELECT extensions.dblink_send_query(
  'kr_a',
  format(
    $$SELECT * FROM public.import_rotation_manifest(%L, %L, %L::jsonb)$$,
    '85000000-0000-0000-0000-000000000001',
    encode(extensions.digest(convert_to(entries::TEXT, 'UTF8'), 'sha256'), 'hex'),
    entries::TEXT
  )
)
FROM (
  SELECT jsonb_build_array(jsonb_build_object(
    'account_id', '82000000-0000-0000-0000-000000000001',
    'table_name', 'whatsapp_config',
    'row_id', '84000000-0000-0000-0000-000000000001',
    'value_path', 'access_token',
    'value_format', 'gcm',
    'legacy_owner', 'current',
    'value_digest', encode(extensions.digest(convert_to(
      (SELECT access_token FROM whatsapp_config
       WHERE id = '84000000-0000-0000-0000-000000000001'),
      'UTF8'
    ), 'sha256'), 'hex')
  )) AS entries
) AS manifest;
CREATE TEMP TABLE reimport_result AS
SELECT * FROM extensions.dblink_get_result('kr_a') AS result(
  manifest_id UUID, revision INTEGER, manifest_digest TEXT,
  status TEXT, reason_code TEXT
);
SELECT extensions.dblink_send_query(
  'kr_b',
  $$WITH claims AS MATERIALIZED (
      SELECT set_config(
        'request.jwt.claims',
        '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}',
        FALSE
      )
    )
    SELECT rotation.* FROM claims
    CROSS JOIN LATERAL public.rotate_encrypted_row(
      '85000000-0000-0000-0000-000000000001',
      '85000000-0000-0000-0000-000000000011',
      'whatsapp_config',
      '84000000-0000-0000-0000-000000000001',
      0,
      (SELECT expected_fingerprint FROM public.rotation_items
       WHERE id = '85000000-0000-0000-0000-000000000011'),
      jsonb_build_object(
        'access_token', repeat('a', 24) || ':' || repeat('b', 32) || ':' || repeat('c', 32)
      )
    ) AS rotation
    WHERE claims.set_config IS NOT NULL$$
);
SELECT pg_sleep(0.2);
SELECT is(
  extensions.dblink_is_busy('kr_b'), 1,
  'reimport-vs-rotate blocks the writer at the run barrier'
);
SELECT extensions.dblink_exec('kr_a', 'COMMIT');
CREATE TEMP TABLE reimport_rotate_result AS
SELECT * FROM extensions.dblink_get_result('kr_b') AS result(
  outcome TEXT, account_id UUID, new_version BIGINT,
  new_fingerprint UUID, reason_code TEXT
);
SELECT is(
  (SELECT reason_code FROM reimport_rotate_result),
  'approval_required',
  'reimport-vs-rotate rejects authorization from the older approval'
);

-- Re-authorize the latest revision for the remaining concurrency scenarios.
INSERT INTO rotation_manifest_approvals (
  manifest_id, run_id, manifest_digest, decision, approver_id
)
SELECT id, run_id, manifest_digest, 'approved',
  '81000000-0000-0000-0000-000000000002'
FROM rotation_manifests
WHERE run_id = '85000000-0000-0000-0000-000000000001' AND revision = 2;
UPDATE rotation_runs SET status = 'running', reason_code = 'started'
WHERE id = '85000000-0000-0000-0000-000000000001';
UPDATE rotation_items
SET status = 'planned', reason_code = 'none', attempts = 0, terminal_at = NULL
WHERE id = '85000000-0000-0000-0000-000000000011';

-- simultaneous-retries: one applies and the matching retry replays safely.
SELECT extensions.dblink_send_query('kr_a', $$WITH claims AS MATERIALIZED (
  SELECT set_config('request.jwt.claims',
    '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}', FALSE)
) SELECT rotation.* FROM claims CROSS JOIN LATERAL public.rotate_encrypted_row(
  '85000000-0000-0000-0000-000000000001',
  '85000000-0000-0000-0000-000000000011', 'whatsapp_config',
  '84000000-0000-0000-0000-000000000001', 0,
  (SELECT expected_fingerprint FROM public.rotation_items
   WHERE id = '85000000-0000-0000-0000-000000000011'),
  jsonb_build_object('access_token',
    repeat('a', 24) || ':' || repeat('b', 32) || ':' || repeat('c', 32))
) AS rotation WHERE claims.set_config IS NOT NULL$$);
SELECT extensions.dblink_send_query('kr_b', $$WITH claims AS MATERIALIZED (
  SELECT set_config('request.jwt.claims',
    '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}', FALSE)
) SELECT rotation.* FROM claims CROSS JOIN LATERAL public.rotate_encrypted_row(
  '85000000-0000-0000-0000-000000000001',
  '85000000-0000-0000-0000-000000000011', 'whatsapp_config',
  '84000000-0000-0000-0000-000000000001', 0,
  (SELECT expected_fingerprint FROM public.rotation_items
   WHERE id = '85000000-0000-0000-0000-000000000011'),
  jsonb_build_object('access_token',
    repeat('a', 24) || ':' || repeat('b', 32) || ':' || repeat('c', 32))
) AS rotation WHERE claims.set_config IS NOT NULL$$);
CREATE TEMP TABLE retry_results (
  outcome TEXT, account_id UUID, new_version BIGINT,
  new_fingerprint UUID, reason_code TEXT
);
INSERT INTO retry_results
SELECT * FROM extensions.dblink_get_result('kr_a') AS result(
  outcome TEXT, account_id UUID, new_version BIGINT,
  new_fingerprint UUID, reason_code TEXT
);
INSERT INTO retry_results
SELECT * FROM extensions.dblink_get_result('kr_b') AS result(
  outcome TEXT, account_id UUID, new_version BIGINT,
  new_fingerprint UUID, reason_code TEXT
);
SELECT set_eq(
  'SELECT outcome FROM retry_results',
  $$VALUES ('applied'::TEXT), ('already_applied'::TEXT)$$,
  'simultaneous-retries produce exactly one write and one replay'
);
SELECT is(
  (SELECT secret_version FROM whatsapp_config
   WHERE id = '84000000-0000-0000-0000-000000000001'),
  1::BIGINT,
  'simultaneous-retries increment row metadata once'
);

-- secret-mutation-vs-rotate: a committed secret change invalidates stale CAS.
SELECT pg_temp.seed_authorized_run(
  '85000000-0000-0000-0000-000000000002',
  '85000000-0000-0000-0000-000000000012',
  ARRAY['access_token']
);
SELECT extensions.dblink_exec('kr_a', 'BEGIN');
SELECT extensions.dblink_exec('kr_a', $$UPDATE public.whatsapp_config
  SET access_token = repeat('d', 24) || ':' || repeat('e', 32) || ':' || repeat('f', 32)
  WHERE id = '84000000-0000-0000-0000-000000000001'$$);
SELECT extensions.dblink_send_query('kr_b', $$WITH claims AS MATERIALIZED (
  SELECT set_config('request.jwt.claims',
    '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}', FALSE)
) SELECT rotation.* FROM claims CROSS JOIN LATERAL public.rotate_encrypted_row(
  '85000000-0000-0000-0000-000000000002',
  '85000000-0000-0000-0000-000000000012', 'whatsapp_config',
  '84000000-0000-0000-0000-000000000001', 1,
  (SELECT expected_fingerprint FROM public.rotation_items
   WHERE id = '85000000-0000-0000-0000-000000000012'),
  jsonb_build_object('access_token',
    repeat('7', 24) || ':' || repeat('8', 32) || ':' || repeat('9', 32))
) AS rotation WHERE claims.set_config IS NOT NULL$$);
SELECT pg_sleep(0.2);
SELECT extensions.dblink_exec('kr_a', 'COMMIT');
CREATE TEMP TABLE secret_mutation_result AS
SELECT * FROM extensions.dblink_get_result('kr_b') AS result(
  outcome TEXT, account_id UUID, new_version BIGINT,
  new_fingerprint UUID, reason_code TEXT
);
SELECT is(
  (SELECT outcome FROM secret_mutation_result), 'conflict',
  'secret-mutation-vs-rotate reports stale CAS conflict'
);

-- unrelated-jsonb-vs-rotate: row-current jsonb_set preserves new properties.
SELECT pg_temp.seed_authorized_run(
  '85000000-0000-0000-0000-000000000003',
  '85000000-0000-0000-0000-000000000013',
  ARRAY['provider_config.apiKey']
);
SELECT extensions.dblink_exec('kr_a', 'BEGIN');
SELECT extensions.dblink_exec('kr_a', $$UPDATE public.whatsapp_config
  SET provider_config = jsonb_set(provider_config, '{region}', '"concurrent"'::jsonb)
  WHERE id = '84000000-0000-0000-0000-000000000001'$$);
SELECT extensions.dblink_send_query('kr_b', $$WITH claims AS MATERIALIZED (
  SELECT set_config('request.jwt.claims',
    '{"role":"service_role","sub":"81000000-0000-0000-0000-000000000002"}', FALSE)
) SELECT rotation.* FROM claims CROSS JOIN LATERAL public.rotate_encrypted_row(
  '85000000-0000-0000-0000-000000000003',
  '85000000-0000-0000-0000-000000000013', 'whatsapp_config',
  '84000000-0000-0000-0000-000000000001', 2,
  (SELECT expected_fingerprint FROM public.rotation_items
   WHERE id = '85000000-0000-0000-0000-000000000013'),
  jsonb_build_object('provider_config.apiKey',
    repeat('0', 24) || ':' || repeat('1', 32) || ':' || repeat('2', 32))
) AS rotation WHERE claims.set_config IS NOT NULL$$);
SELECT pg_sleep(0.2);
SELECT is(
  extensions.dblink_is_busy('kr_b'), 1,
  'unrelated-jsonb-vs-rotate waits for the encrypted-row lock'
);
SELECT extensions.dblink_exec('kr_a', 'COMMIT');
CREATE TEMP TABLE jsonb_result AS
SELECT * FROM extensions.dblink_get_result('kr_b') AS result(
  outcome TEXT, account_id UUID, new_version BIGINT,
  new_fingerprint UUID, reason_code TEXT
);
SELECT is(
  (SELECT outcome FROM jsonb_result), 'applied',
  'unrelated-jsonb-vs-rotate still applies the secret update'
);
SELECT is(
  (SELECT provider_config ->> 'region' FROM whatsapp_config
   WHERE id = '84000000-0000-0000-0000-000000000001'),
  'concurrent',
  'unrelated-jsonb-vs-rotate preserves the concurrent property'
);

SELECT extensions.dblink_disconnect('kr_a');
SELECT extensions.dblink_disconnect('kr_b');
SELECT set_config('app.key_rotation_purge', 'authorized', FALSE);
UPDATE rotation_audit_events SET item_id = NULL
WHERE run_id::TEXT LIKE '85000000-%';
DELETE FROM rotation_manifest_approvals WHERE run_id::TEXT LIKE '85000000-%';
DELETE FROM rotation_manifest_entries WHERE run_id::TEXT LIKE '85000000-%';
DELETE FROM rotation_manifests WHERE run_id::TEXT LIKE '85000000-%';
DELETE FROM rotation_items WHERE run_id::TEXT LIKE '85000000-%';
DELETE FROM rotation_audit_events WHERE run_id::TEXT LIKE '85000000-%';
DELETE FROM rotation_runs WHERE id::TEXT LIKE '85000000-%';
DELETE FROM whatsapp_config WHERE id = '84000000-0000-0000-0000-000000000001';
DELETE FROM profiles WHERE user_id::TEXT LIKE '81000000-%';
DELETE FROM accounts WHERE id = '82000000-0000-0000-0000-000000000001';
DELETE FROM auth.users WHERE id::TEXT LIKE '81000000-%';
UPDATE rotation_runtime_control
SET operations_enabled = FALSE, disabled_reason = 'not_enabled', updated_by = NULL
WHERE singleton;
SELECT set_config('app.key_rotation_purge', '', FALSE);
SELECT * FROM finish();
