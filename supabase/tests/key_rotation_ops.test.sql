BEGIN;

CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SET search_path = public, extensions;

SELECT plan(65);

-- Task 4.1 — expand-only schema and least-privilege foundation.
SELECT has_table('public', 'rotation_runs', 'rotation_runs exists');
SELECT has_table('public', 'rotation_items', 'rotation_items exists');
SELECT has_table('public', 'rotation_manifests', 'rotation_manifests exists');
SELECT has_table('public', 'rotation_manifest_entries', 'manifest entries exist');
SELECT has_table('public', 'rotation_manifest_approvals', 'manifest approvals exist');
SELECT has_table('public', 'rotation_audit_events', 'rotation audit exists');

SELECT has_column('public', 'whatsapp_config', 'secret_version');
SELECT has_column('public', 'whatsapp_config', 'secret_fingerprint');
SELECT has_column('public', 'salesforce_config', 'secret_version');
SELECT has_column('public', 'salesforce_config', 'secret_fingerprint');
SELECT has_column('public', 'ai_configs', 'secret_version');
SELECT has_column('public', 'ai_configs', 'secret_fingerprint');
SELECT has_column('public', 'webhook_endpoints', 'secret_version');
SELECT has_column('public', 'webhook_endpoints', 'secret_fingerprint');

SELECT col_not_null('public', 'rotation_runs', 'status');
SELECT col_not_null('public', 'rotation_items', 'reason_code');
SELECT col_not_null('public', 'rotation_manifest_entries', 'legacy_owner');
SELECT col_not_null('public', 'rotation_audit_events', 'event_type');

SELECT ok(
  NOT has_table_privilege('anon', 'public.rotation_runs', 'SELECT'),
  'anon cannot read rotation runs'
);
SELECT ok(
  NOT has_table_privilege('authenticated', 'public.rotation_items', 'SELECT'),
  'authenticated cannot read rotation items directly'
);
SELECT ok(
  NOT has_table_privilege('service_role', 'public.rotation_manifest_entries', 'SELECT'),
  'service role uses functions rather than direct manifest reads'
);

SELECT has_function('public', 'disable_key_rotation_operations', ARRAY['text']);
SELECT has_function('public', 'assert_key_rotation_rollback_safe', ARRAY[]::text[]);
SELECT is(
  (SELECT operations_enabled FROM rotation_runtime_control WHERE singleton),
  FALSE,
  'rotation starts disabled'
);
SELECT ok(
  (SELECT purge_after IS NULL FROM rotation_runs LIMIT 1) IS NOT FALSE,
  'retention timestamp is nullable until retirement'
);

-- Task 4.2 — fixed service-only RPC and safe privileges.
SELECT has_function(
  'public',
  'rotate_encrypted_row',
  ARRAY['uuid', 'uuid', 'text', 'uuid', 'bigint', 'uuid', 'jsonb']
);
SELECT ok(
  has_function_privilege(
    'service_role',
    'public.rotate_encrypted_row(uuid,uuid,text,uuid,bigint,uuid,jsonb)',
    'EXECUTE'
  ),
  'service role can execute rotation RPC'
);
SELECT ok(
  NOT has_function_privilege(
    'authenticated',
    'public.rotate_encrypted_row(uuid,uuid,text,uuid,bigint,uuid,jsonb)',
    'EXECUTE'
  ),
  'authenticated cannot execute rotation RPC'
);
SELECT ok(
  NOT has_function_privilege(
    'anon',
    'public.rotate_encrypted_row(uuid,uuid,text,uuid,bigint,uuid,jsonb)',
    'EXECUTE'
  ),
  'anon cannot execute rotation RPC'
);

SELECT lives_ok(
  $$UPDATE rotation_runtime_control
    SET operations_enabled = TRUE, disabled_reason = 'maintenance'
    WHERE singleton$$,
  'test enables the otherwise inert contract locally'
);

SELECT throws_ok(
  $$SELECT * FROM rotate_encrypted_row(
    gen_random_uuid(), gen_random_uuid(), 'contacts', gen_random_uuid(),
    0, gen_random_uuid(), '{}'::jsonb
  )$$,
  '42501',
  'key rotation authorization failed',
  'non-service caller is rejected before payload handling'
);

SELECT ok(
  pg_get_functiondef(
    'rotate_encrypted_row(uuid,uuid,text,uuid,bigint,uuid,jsonb)'::regprocedure
  ) !~* 'execute[[:space:]]+format',
  'RPC has no dynamic SQL table interpolation'
);
SELECT ok(
  pg_get_functiondef(
    'rotate_encrypted_row(uuid,uuid,text,uuid,bigint,uuid,jsonb)'::regprocedure
  ) !~* 'raise[^;]*(p_values|sqlerrm)',
  'RPC errors cannot echo values or raw database errors'
);
SELECT ok(
  pg_get_functiondef(
    'rotate_encrypted_row(uuid,uuid,text,uuid,bigint,uuid,jsonb)'::regprocedure
  ) ~ 'secret_version = p_expected_version',
  'RPC compares the non-secret version'
);
SELECT ok(
  pg_get_functiondef(
    'rotate_encrypted_row(uuid,uuid,text,uuid,bigint,uuid,jsonb)'::regprocedure
  ) ~ 'secret_fingerprint = p_expected_fingerprint',
  'RPC compares the opaque fingerprint'
);

-- Task 4.3 — row/path-scoped ownership and dual control.
SELECT has_function(
  'public', 'import_rotation_manifest', ARRAY['uuid', 'text', 'jsonb']
);
SELECT has_function(
  'public', 'approve_rotation_manifest', ARRAY['uuid', 'text', 'text']
);
SELECT has_function(
  'public', 'rotation_manifest_entry_digest_matches',
  ARRAY['rotation_manifest_entries']
);
SELECT has_function(
  'public', 'rotation_item_has_approved_manifest', ARRAY['uuid', 'uuid']
);
SELECT ok(
  has_function_privilege(
    'authenticated',
    'public.import_rotation_manifest(uuid,text,jsonb)',
    'EXECUTE'
  ),
  'authenticated preparers call the guarded import RPC'
);
SELECT ok(
  has_function_privilege(
    'authenticated',
    'public.approve_rotation_manifest(uuid,text,text)',
    'EXECUTE'
  ),
  'authenticated approvers call the guarded approval RPC'
);
SELECT ok(
  pg_get_functiondef(
    'approve_rotation_manifest(uuid,text,text)'::regprocedure
  ) ~ 'v_preparer_id = v_approver_id',
  'approval enforces separation of duties'
);
SELECT ok(
  pg_get_functiondef(
    'rotation_item_has_approved_manifest(uuid,uuid)'::regprocedure
  ) ~ 'ORDER BY revision DESC',
  'only the latest manifest revision can authorize rotation'
);
SELECT ok(
  pg_get_functiondef(
    'approve_rotation_manifest(uuid,text,text)'::regprocedure
  ) ~ 'legacy_owner = ''unknown''',
  'unknown legacy ownership blocks approval'
);
SELECT ok(
  pg_get_functiondef(
    'import_rotation_manifest(uuid,text,jsonb)'::regprocedure
  ) !~* '(plaintext|ciphertext|secret_value)',
  'manifest import accepts evidence only, never secrets'
);

-- Behavioral fixtures. These rows exist only inside this rolled-back test.
INSERT INTO auth.users (
  id, aud, role, email, encrypted_password, raw_app_meta_data,
  raw_user_meta_data, created_at, updated_at
) VALUES
  ('10000000-0000-0000-0000-000000000001', 'authenticated', 'authenticated',
   'rotation-preparer@example.test', '', '{}'::jsonb, '{}'::jsonb, now(), now()),
  ('10000000-0000-0000-0000-000000000002', 'authenticated', 'authenticated',
   'rotation-approver@example.test', '', '{}'::jsonb, '{}'::jsonb, now(), now());

INSERT INTO accounts (id, name, owner_user_id)
VALUES (
  '20000000-0000-0000-0000-000000000001',
  'Rotation test account',
  '10000000-0000-0000-0000-000000000001'
);

INSERT INTO profiles (
  id, user_id, full_name, email, account_id, account_role
) VALUES
  ('30000000-0000-0000-0000-000000000001',
   '10000000-0000-0000-0000-000000000001', 'Preparer',
   'rotation-preparer@example.test', '20000000-0000-0000-0000-000000000001',
   'owner'),
  ('30000000-0000-0000-0000-000000000002',
   '10000000-0000-0000-0000-000000000002', 'Approver',
   'rotation-approver@example.test', '20000000-0000-0000-0000-000000000001',
   'admin');

INSERT INTO whatsapp_config (
  id, user_id, account_id, phone_number_id, access_token, provider_config
) VALUES (
  '40000000-0000-0000-0000-000000000001',
  '10000000-0000-0000-0000-000000000001',
  '20000000-0000-0000-0000-000000000001',
  'rotation-test-phone',
  repeat('1', 24) || ':' || repeat('2', 32) || ':' || repeat('3', 32),
  jsonb_build_object(
    'apiKey', repeat('4', 24) || ':' || repeat('5', 32) || ':' || repeat('6', 32),
    'region', 'keep-me'
  )
);

INSERT INTO webhook_endpoints (
  id, account_id, created_by, url, secret
) VALUES (
  '40000000-0000-0000-0000-000000000002',
  '20000000-0000-0000-0000-000000000001',
  '10000000-0000-0000-0000-000000000001',
  'https://rotation.invalid.test/hook',
  repeat('7', 24) || ':' || repeat('8', 32) || ':' || repeat('9', 32)
);

INSERT INTO rotation_runs (
  id, account_id, mode, current_key_fingerprint, previous_key_fingerprint
) VALUES (
  '50000000-0000-0000-0000-000000000001',
  '20000000-0000-0000-0000-000000000001',
  'apply',
  '60000000-0000-0000-0000-000000000001',
  '60000000-0000-0000-0000-000000000002'
);

INSERT INTO rotation_items (
  id, run_id, sequence, account_id, table_name, row_id, target_paths,
  expected_version, expected_fingerprint
)
SELECT
  '70000000-0000-0000-0000-000000000001',
  '50000000-0000-0000-0000-000000000001',
  1,
  account_id,
  'whatsapp_config',
  id,
  ARRAY['access_token', 'provider_config.apiKey'],
  secret_version,
  secret_fingerprint
FROM whatsapp_config
WHERE id = '40000000-0000-0000-0000-000000000001';

INSERT INTO rotation_items (
  id, run_id, sequence, account_id, table_name, row_id, target_paths,
  expected_version, expected_fingerprint
)
SELECT
  '70000000-0000-0000-0000-000000000002',
  '50000000-0000-0000-0000-000000000001',
  2,
  account_id,
  'webhook_endpoints',
  id,
  ARRAY['secret'],
  secret_version,
  secret_fingerprint
FROM webhook_endpoints
WHERE id = '40000000-0000-0000-0000-000000000002';

CREATE TEMP TABLE rotation_test_manifest AS
WITH source AS (
  SELECT jsonb_build_array(
    jsonb_build_object(
      'account_id', '20000000-0000-0000-0000-000000000001',
      'table_name', 'whatsapp_config',
      'row_id', '40000000-0000-0000-0000-000000000001',
      'value_path', 'access_token', 'value_format', 'gcm',
      'legacy_owner', 'current',
      'value_digest', encode(digest(convert_to(access_token, 'UTF8'), 'sha256'), 'hex')
    ),
    jsonb_build_object(
      'account_id', '20000000-0000-0000-0000-000000000001',
      'table_name', 'whatsapp_config',
      'row_id', '40000000-0000-0000-0000-000000000001',
      'value_path', 'provider_config.apiKey', 'value_format', 'gcm',
      'legacy_owner', 'current',
      'value_digest', encode(digest(convert_to(provider_config ->> 'apiKey', 'UTF8'), 'sha256'), 'hex')
    ),
    jsonb_build_object(
      'account_id', '20000000-0000-0000-0000-000000000001',
      'table_name', 'webhook_endpoints',
      'row_id', '40000000-0000-0000-0000-000000000002',
      'value_path', 'secret', 'value_format', 'gcm',
      'legacy_owner', 'current',
      'value_digest', encode(digest(convert_to(
        (SELECT secret FROM webhook_endpoints
         WHERE id = '40000000-0000-0000-0000-000000000002'),
        'UTF8'
      ), 'sha256'), 'hex')
    )
  ) AS entries
  FROM whatsapp_config
  WHERE id = '40000000-0000-0000-0000-000000000001'
), canonical AS (
  SELECT entries, (
    SELECT jsonb_agg(entry ORDER BY
      entry ->> 'account_id', entry ->> 'table_name', entry ->> 'row_id',
      entry ->> 'value_path'
    )
    FROM jsonb_array_elements(entries) AS manifest_entries(entry)
  ) AS canonical_entries
  FROM source
)
SELECT
  entries,
  encode(digest(convert_to(canonical_entries::text, 'UTF8'), 'sha256'), 'hex')
    AS manifest_digest
FROM canonical;

SELECT set_config(
  'request.jwt.claims',
  '{"role":"authenticated","sub":"10000000-0000-0000-0000-000000000001"}',
  TRUE
);

SELECT throws_ok(
  $$SELECT * FROM import_rotation_manifest(
    '50000000-0000-0000-0000-000000000001', repeat('f', 64),
    (SELECT entries FROM rotation_test_manifest)
  )$$,
  '22000', 'manifest digest mismatch',
  'tampered manifest digest is rejected'
);
SELECT throws_ok(
  $$SELECT * FROM import_rotation_manifest(
    '50000000-0000-0000-0000-000000000001',
    (SELECT manifest_digest FROM rotation_test_manifest),
    (SELECT entries || jsonb_build_array(entries -> 0) FROM rotation_test_manifest)
  )$$,
  '22023', 'conflicting manifest evidence',
  'duplicate row/path ownership collision is rejected'
);
SELECT is(
  (SELECT status FROM import_rotation_manifest(
    '50000000-0000-0000-0000-000000000001',
    (SELECT manifest_digest FROM rotation_test_manifest),
    (SELECT entries FROM rotation_test_manifest)
  )),
  'awaiting_approval',
  'valid evidence creates revision one'
);
SELECT is(
  (SELECT reason_code FROM approve_rotation_manifest(
    '50000000-0000-0000-0000-000000000001',
    (SELECT manifest_digest FROM rotation_test_manifest), 'approved'
  )),
  'role_collision',
  'preparer cannot approve their own manifest'
);

SELECT set_config(
  'request.jwt.claims',
  '{"role":"authenticated","sub":"10000000-0000-0000-0000-000000000002"}',
  TRUE
);
SELECT is(
  (SELECT outcome FROM approve_rotation_manifest(
    '50000000-0000-0000-0000-000000000001',
    (SELECT manifest_digest FROM rotation_test_manifest), 'approved'
  )),
  'approved',
  'distinct account administrator approves manifest'
);
SELECT ok(
  rotation_item_has_approved_manifest(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000001'
  ),
  'approved row/path evidence authorizes its item'
);

SELECT set_config(
  'request.jwt.claims',
  '{"role":"authenticated","sub":"10000000-0000-0000-0000-000000000001"}',
  TRUE
);
SELECT is(
  (SELECT reason_code FROM import_rotation_manifest(
    '50000000-0000-0000-0000-000000000001',
    (SELECT manifest_digest FROM rotation_test_manifest),
    (SELECT entries FROM rotation_test_manifest)
  )),
  'manifest_reimported',
  'reimport creates a new revision and invalidates approval'
);
SELECT ok(
  NOT rotation_item_has_approved_manifest(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000001'
  ),
  'older approval cannot authorize a reimported manifest'
);

SELECT set_config(
  'request.jwt.claims',
  '{"role":"authenticated","sub":"10000000-0000-0000-0000-000000000002"}',
  TRUE
);
SELECT is(
  (SELECT outcome FROM approve_rotation_manifest(
    '50000000-0000-0000-0000-000000000001',
    (SELECT manifest_digest FROM rotation_test_manifest), 'approved'
  )),
  'approved',
  'latest revision receives its own approval'
);
SELECT ok(
  rotation_item_has_approved_manifest(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000001'
  ),
  'latest approval restores item authorization'
);

UPDATE rotation_runtime_control
SET operations_enabled = TRUE, disabled_reason = 'maintenance'
WHERE singleton;
SELECT set_config(
  'request.jwt.claims',
  '{"role":"service_role","sub":"10000000-0000-0000-0000-000000000002"}',
  TRUE
);

SELECT is(
  (SELECT outcome FROM rotate_encrypted_row(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000001',
    'whatsapp_config',
    '40000000-0000-0000-0000-000000000001',
    0,
    (SELECT expected_fingerprint FROM rotation_items
     WHERE id = '70000000-0000-0000-0000-000000000001'),
    jsonb_build_object(
      'access_token', repeat('a', 24) || ':' || repeat('b', 32) || ':' || repeat('c', 32),
      'provider_config.apiKey', repeat('d', 24) || ':' || repeat('e', 32) || ':' || repeat('f', 32)
    )
  )),
  'applied',
  'scalar and JSON values rotate atomically'
);
SELECT is(
  (SELECT provider_config ->> 'region' FROM whatsapp_config
   WHERE id = '40000000-0000-0000-0000-000000000001'),
  'keep-me',
  'JSON rotation preserves unrelated properties'
);
SELECT is(
  (SELECT secret_version FROM whatsapp_config
   WHERE id = '40000000-0000-0000-0000-000000000001'),
  1::bigint,
  'atomic rotation bumps the non-secret row version once'
);
SELECT is(
  (SELECT outcome FROM rotate_encrypted_row(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000001',
    'whatsapp_config',
    '40000000-0000-0000-0000-000000000001',
    0,
    (SELECT expected_fingerprint FROM rotation_items
     WHERE id = '70000000-0000-0000-0000-000000000001'),
    jsonb_build_object(
      'access_token', repeat('0', 24) || ':' || repeat('0', 32) || ':' || repeat('0', 32),
      'provider_config.apiKey', repeat('0', 24) || ':' || repeat('0', 32) || ':' || repeat('0', 32)
    )
  )),
  'already_applied',
  'replay returns the committed result without rewriting'
);

UPDATE webhook_endpoints
SET secret = repeat('a', 24) || ':' || repeat('a', 32) || ':' || repeat('a', 32)
WHERE id = '40000000-0000-0000-0000-000000000002';
SELECT lives_ok(
  $$SELECT secret_version FROM webhook_endpoints
    WHERE id = '40000000-0000-0000-0000-000000000002'$$,
  'concurrent secret update completes before stale RPC attempt'
);
SELECT is(
  (SELECT outcome FROM rotate_encrypted_row(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000002',
    'webhook_endpoints',
    '40000000-0000-0000-0000-000000000002',
    0,
    (SELECT expected_fingerprint FROM rotation_items
     WHERE id = '70000000-0000-0000-0000-000000000002'),
    jsonb_build_object(
      'secret', repeat('b', 24) || ':' || repeat('b', 32) || ':' || repeat('b', 32)
    )
  )),
  'conflict',
  'stale version/fingerprint produces a safe conflict'
);

SELECT throws_ok(
  $$UPDATE rotation_manifests SET entry_count = entry_count$$,
  '55000', 'rotation evidence is immutable',
  'manifest evidence cannot be tampered with'
);

UPDATE rotation_runtime_control
SET operations_enabled = FALSE, disabled_reason = 'maintenance'
WHERE singleton;
SELECT throws_ok(
  $$SELECT assert_key_rotation_rollback_safe()$$,
  '55000', 'retained key rotation evidence blocks destructive rollback',
  'retained evidence blocks destructive rollback'
);

CREATE TEMP TABLE rotation_test_unknown AS
WITH changed AS (
  SELECT jsonb_set(
    jsonb_set(entries, '{0,value_format}', '"cbc"'::jsonb),
    '{0,legacy_owner}', '"unknown"'::jsonb
  ) AS entries
  FROM rotation_test_manifest
), canonical AS (
  SELECT entries, (
    SELECT jsonb_agg(entry ORDER BY
      entry ->> 'account_id', entry ->> 'table_name', entry ->> 'row_id',
      entry ->> 'value_path'
    ) FROM jsonb_array_elements(entries) AS manifest_entries(entry)
  ) AS canonical_entries
  FROM changed
)
SELECT entries,
  encode(digest(convert_to(canonical_entries::text, 'UTF8'), 'sha256'), 'hex')
    AS manifest_digest
FROM canonical;

SELECT set_config(
  'request.jwt.claims',
  '{"role":"authenticated","sub":"10000000-0000-0000-0000-000000000001"}',
  TRUE
);
SELECT is(
  (SELECT status FROM import_rotation_manifest(
    '50000000-0000-0000-0000-000000000001',
    (SELECT manifest_digest FROM rotation_test_unknown),
    (SELECT entries FROM rotation_test_unknown)
  )),
  'awaiting_approval',
  'unknown evidence is retained for explicit review'
);
SELECT set_config(
  'request.jwt.claims',
  '{"role":"authenticated","sub":"10000000-0000-0000-0000-000000000002"}',
  TRUE
);
SELECT is(
  (SELECT reason_code FROM approve_rotation_manifest(
    '50000000-0000-0000-0000-000000000001',
    (SELECT manifest_digest FROM rotation_test_unknown), 'approved'
  )),
  'unknown_ownership',
  'unknown CBC ownership fails closed'
);

SELECT * FROM finish();
ROLLBACK;
