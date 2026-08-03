BEGIN;

CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SET search_path = public, extensions;

SELECT plan(104);

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
SELECT set_config('request.jwt.claims', '{"role":123}', TRUE);
SELECT throws_ok(
  $$SELECT * FROM rotate_encrypted_row(
    gen_random_uuid(), gen_random_uuid(), 'contacts', gen_random_uuid(),
    0, gen_random_uuid(), '{}'::jsonb
  )$$,
  '42501', 'key rotation authorization failed',
  'malformed role claims fail closed'
);
SELECT set_config('request.jwt.claims', '{"role":"anon"}', TRUE);
SELECT throws_ok(
  $$SELECT * FROM rotate_encrypted_row(
    gen_random_uuid(), gen_random_uuid(), 'contacts', gen_random_uuid(),
    0, gen_random_uuid(), '{}'::jsonb
  )$$,
  '42501', 'key rotation authorization failed',
  'anon claims cannot call service-role rotation'
);
SELECT set_config('request.jwt.claims', '{"role":"authenticated"}', TRUE);
SELECT throws_ok(
  $$SELECT * FROM rotate_encrypted_row(
    gen_random_uuid(), gen_random_uuid(), 'contacts', gen_random_uuid(),
    0, gen_random_uuid(), '{}'::jsonb
  )$$,
  '42501', 'key rotation authorization failed',
  'authenticated claims cannot call service-role rotation'
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
   'rotation-approver@example.test', '', '{}'::jsonb, '{}'::jsonb, now(), now()),
  ('10000000-0000-0000-0000-000000000003', 'authenticated', 'authenticated',
   'rotation-outsider@example.test', '', '{}'::jsonb, '{}'::jsonb, now(), now());

INSERT INTO accounts (id, name, owner_user_id)
VALUES (
  '20000000-0000-0000-0000-000000000001',
  'Rotation test account',
  '10000000-0000-0000-0000-000000000001'
), (
  '20000000-0000-0000-0000-000000000002',
  'Other rotation account',
  '10000000-0000-0000-0000-000000000003'
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
    'admin'),
  ('30000000-0000-0000-0000-000000000003',
   '10000000-0000-0000-0000-000000000003', 'Outsider',
   'rotation-outsider@example.test', '20000000-0000-0000-0000-000000000002',
   'owner');

INSERT INTO whatsapp_config (
  id, user_id, account_id, phone_number_id, access_token, verify_token,
  provider_config
) VALUES (
  '40000000-0000-0000-0000-000000000001',
  '10000000-0000-0000-0000-000000000001',
  '20000000-0000-0000-0000-000000000001',
  'rotation-test-phone',
  repeat('1', 24) || ':' || repeat('2', 32) || ':' || repeat('3', 32),
  repeat('2', 24) || ':' || repeat('3', 32) || ':' || repeat('4', 32),
  jsonb_build_object(
    'apiKey', repeat('4', 24) || ':' || repeat('5', 32) || ':' || repeat('6', 32),
    'secret', repeat('5', 24) || ':' || repeat('6', 32) || ':' || repeat('7', 32),
    'region', 'keep-me'
  )
);

INSERT INTO salesforce_config (
  id, account_id, instance_url, client_id, client_secret, username,
  password, security_token, webhook_secret
) VALUES (
  '40000000-0000-0000-0000-000000000003',
  '20000000-0000-0000-0000-000000000001',
  'https://salesforce.example.test',
  repeat('1', 24) || ':' || repeat('1', 32) || ':' || repeat('1', 32),
  repeat('2', 24) || ':' || repeat('2', 32) || ':' || repeat('2', 32),
  repeat('3', 24) || ':' || repeat('3', 32) || ':' || repeat('3', 32),
  repeat('4', 24) || ':' || repeat('4', 32) || ':' || repeat('4', 32),
  repeat('5', 24) || ':' || repeat('5', 32) || ':' || repeat('5', 32),
  repeat('6', 24) || ':' || repeat('6', 32) || ':' || repeat('6', 32)
);

INSERT INTO ai_configs (
  id, account_id, created_by, provider, model, api_key, embeddings_api_key
) VALUES (
  '40000000-0000-0000-0000-000000000004',
  '20000000-0000-0000-0000-000000000001',
  '10000000-0000-0000-0000-000000000001',
  'openai', 'test-model',
  repeat('7', 24) || ':' || repeat('7', 32) || ':' || repeat('7', 32),
  repeat('8', 24) || ':' || repeat('8', 32) || ':' || repeat('8', 32)
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
  id, account_id, mode, current_key_fingerprint, previous_key_fingerprint,
  expected_items
) VALUES (
  '50000000-0000-0000-0000-000000000001',
  '20000000-0000-0000-0000-000000000001',
  'apply',
  '60000000-0000-0000-0000-000000000001',
  '60000000-0000-0000-0000-000000000002',
  4
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
  ARRAY[
    'access_token', 'verify_token', 'provider_config.apiKey',
    'provider_config.secret'
  ],
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

INSERT INTO rotation_items (
  id, run_id, sequence, account_id, table_name, row_id, target_paths,
  expected_version, expected_fingerprint
)
SELECT
  '70000000-0000-0000-0000-000000000003',
  '50000000-0000-0000-0000-000000000001',
  3,
  account_id,
  'salesforce_config',
  id,
  ARRAY[
    'client_id', 'client_secret', 'username', 'password',
    'security_token', 'webhook_secret'
  ],
  secret_version,
  secret_fingerprint
FROM salesforce_config
WHERE id = '40000000-0000-0000-0000-000000000003';

INSERT INTO rotation_items (
  id, run_id, sequence, account_id, table_name, row_id, target_paths,
  expected_version, expected_fingerprint
)
SELECT
  '70000000-0000-0000-0000-000000000004',
  '50000000-0000-0000-0000-000000000001',
  4,
  account_id,
  'ai_configs',
  id,
  ARRAY['api_key', 'embeddings_api_key'],
  secret_version,
  secret_fingerprint
FROM ai_configs
WHERE id = '40000000-0000-0000-0000-000000000004';

CREATE TEMP TABLE rotation_test_manifest AS
WITH source_values AS (
  SELECT
    item.account_id,
    item.table_name,
    item.row_id,
    path.value_path,
    CASE item.table_name
      WHEN 'whatsapp_config' THEN (
        SELECT CASE path.value_path
          WHEN 'access_token' THEN config.access_token
          WHEN 'verify_token' THEN config.verify_token
          WHEN 'provider_config.apiKey' THEN config.provider_config ->> 'apiKey'
          WHEN 'provider_config.secret' THEN config.provider_config ->> 'secret'
        END
        FROM whatsapp_config AS config WHERE config.id = item.row_id
      )
      WHEN 'salesforce_config' THEN (
        SELECT CASE path.value_path
          WHEN 'client_id' THEN config.client_id
          WHEN 'client_secret' THEN config.client_secret
          WHEN 'username' THEN config.username
          WHEN 'password' THEN config.password
          WHEN 'security_token' THEN config.security_token
          WHEN 'webhook_secret' THEN config.webhook_secret
        END
        FROM salesforce_config AS config WHERE config.id = item.row_id
      )
      WHEN 'ai_configs' THEN (
        SELECT CASE path.value_path
          WHEN 'api_key' THEN config.api_key
          WHEN 'embeddings_api_key' THEN config.embeddings_api_key
        END
        FROM ai_configs AS config WHERE config.id = item.row_id
      )
      WHEN 'webhook_endpoints' THEN (
        SELECT endpoint.secret FROM webhook_endpoints AS endpoint
        WHERE endpoint.id = item.row_id AND path.value_path = 'secret'
      )
    END AS encrypted_value
  FROM rotation_items AS item
  CROSS JOIN LATERAL unnest(item.target_paths) AS path(value_path)
  WHERE item.run_id = '50000000-0000-0000-0000-000000000001'
), entries AS (
  SELECT jsonb_agg(
    jsonb_build_object(
      'account_id', account_id::TEXT,
      'table_name', table_name,
      'row_id', row_id::TEXT,
      'value_path', value_path,
      'value_format', 'gcm',
      'legacy_owner', 'current',
      'value_digest', encode(
        extensions.digest(convert_to(encrypted_value, 'UTF8'), 'sha256'),
        'hex'
      )
    ) ORDER BY account_id, table_name, row_id, value_path
  ) AS canonical_entries
  FROM source_values
)
SELECT
  canonical_entries AS entries,
  encode(extensions.digest(
    convert_to(canonical_entries::TEXT, 'UTF8'), 'sha256'
  ), 'hex')
    AS manifest_digest
FROM entries;

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
  '{"role":"authenticated","sub":"10000000-0000-0000-0000-000000000003"}',
  TRUE
);
SELECT throws_ok(
  $$SELECT * FROM approve_rotation_manifest(
    '50000000-0000-0000-0000-000000000001',
    (SELECT manifest_digest FROM rotation_test_manifest), 'approved'
  )$$,
  '42501', 'manifest authorization failed',
  'administrator from another account cannot approve the manifest'
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
SELECT is(
  (SELECT COUNT(*)::INTEGER
   FROM rotation_manifest_entries
   WHERE manifest_id = (
     SELECT id FROM rotation_manifests
     WHERE run_id = '50000000-0000-0000-0000-000000000001'
     ORDER BY revision DESC LIMIT 1
   )),
  13,
  'manifest contains every allow-listed encrypted value path'
);
SELECT ok(
  (SELECT bool_and(rotation_manifest_entry_digest_matches(entry))
   FROM rotation_manifest_entries AS entry
   WHERE manifest_id = (
     SELECT id FROM rotation_manifests
     WHERE run_id = '50000000-0000-0000-0000-000000000001'
     ORDER BY revision DESC LIMIT 1
   )),
  'digest helper executes successfully for all thirteen paths'
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
  'manifest_replayed',
  'identical import returns the existing revision'
);
SELECT ok(
  rotation_item_has_approved_manifest(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000001'
  ),
  'identical import preserves the existing approval'
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
  'already_recorded',
  'approval retry returns the existing approval'
);
SELECT ok(
  rotation_item_has_approved_manifest(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000001'
  ),
  'preserved approval keeps item authorization'
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
  (SELECT outcome FROM start_key_rotation_run(
    '50000000-0000-0000-0000-000000000001'
  )),
  'started',
  'approved run starts through the service-role lifecycle RPC'
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
      'verify_token', repeat('b', 24) || ':' || repeat('c', 32) || ':' || repeat('d', 32),
      'provider_config.apiKey', repeat('d', 24) || ':' || repeat('e', 32) || ':' || repeat('f', 32),
      'provider_config.secret', repeat('e', 24) || ':' || repeat('f', 32) || ':' || repeat('0', 32)
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
      'access_token', repeat('a', 24) || ':' || repeat('b', 32) || ':' || repeat('c', 32),
      'verify_token', repeat('b', 24) || ':' || repeat('c', 32) || ':' || repeat('d', 32),
      'provider_config.apiKey', repeat('d', 24) || ':' || repeat('e', 32) || ':' || repeat('f', 32),
      'provider_config.secret', repeat('e', 24) || ':' || repeat('f', 32) || ':' || repeat('0', 32)
    )
  )),
  'already_applied',
  'matching replay returns the committed result without rewriting'
);
UPDATE whatsapp_config
SET access_token = repeat('9', 24) || ':' || repeat('8', 32) || ':' || repeat('7', 32)
WHERE id = '40000000-0000-0000-0000-000000000001';
SELECT is(
  (SELECT reason_code FROM rotate_encrypted_row(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000001',
    'whatsapp_config',
    '40000000-0000-0000-0000-000000000001',
    0,
    (SELECT expected_fingerprint FROM rotation_items
     WHERE id = '70000000-0000-0000-0000-000000000001'),
    jsonb_build_object(
      'access_token', repeat('a', 24) || ':' || repeat('b', 32) || ':' || repeat('c', 32),
      'verify_token', repeat('b', 24) || ':' || repeat('c', 32) || ':' || repeat('d', 32),
      'provider_config.apiKey', repeat('d', 24) || ':' || repeat('e', 32) || ':' || repeat('f', 32),
      'provider_config.secret', repeat('e', 24) || ':' || repeat('f', 32) || ':' || repeat('0', 32)
    )
  )),
  'version_conflict',
  'applied replay revalidates locked current row metadata'
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
      'verify_token', repeat('0', 24) || ':' || repeat('0', 32) || ':' || repeat('0', 32),
      'provider_config.apiKey', repeat('0', 24) || ':' || repeat('0', 32) || ':' || repeat('0', 32),
      'provider_config.secret', repeat('0', 24) || ':' || repeat('0', 32) || ':' || repeat('0', 32)
    )
  )),
  'conflict',
  'replay with a different replacement payload fails closed'
);

SELECT is(
  (SELECT outcome FROM rotate_encrypted_row(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000003',
    'salesforce_config',
    '40000000-0000-0000-0000-000000000003',
    0,
    (SELECT expected_fingerprint FROM rotation_items
     WHERE id = '70000000-0000-0000-0000-000000000003'),
    jsonb_build_object(
      'client_id', repeat('a', 24) || ':' || repeat('1', 32) || ':' || repeat('2', 32),
      'client_secret', repeat('b', 24) || ':' || repeat('2', 32) || ':' || repeat('3', 32),
      'username', repeat('c', 24) || ':' || repeat('3', 32) || ':' || repeat('4', 32),
      'password', repeat('d', 24) || ':' || repeat('4', 32) || ':' || repeat('5', 32),
      'security_token', repeat('e', 24) || ':' || repeat('5', 32) || ':' || repeat('6', 32),
      'webhook_secret', repeat('f', 24) || ':' || repeat('6', 32) || ':' || repeat('7', 32)
    )
  )),
  'applied',
  'Salesforce scalar values rotate atomically on the fresh schema'
);
SELECT is(
  (SELECT webhook_secret FROM salesforce_config
   WHERE id = '40000000-0000-0000-0000-000000000003'),
  repeat('f', 24) || ':' || repeat('6', 32) || ':' || repeat('7', 32),
  'Salesforce webhook_secret exists and receives the replacement value'
);
SELECT is(
  (SELECT outcome FROM rotate_encrypted_row(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000004',
    'ai_configs',
    '40000000-0000-0000-0000-000000000004',
    0,
    (SELECT expected_fingerprint FROM rotation_items
     WHERE id = '70000000-0000-0000-0000-000000000004'),
    jsonb_build_object(
      'api_key', repeat('1', 24) || ':' || repeat('a', 32) || ':' || repeat('b', 32),
      'embeddings_api_key', repeat('2', 24) || ':' || repeat('b', 32) || ':' || repeat('c', 32)
    )
  )),
  'applied',
  'AI scalar values rotate atomically'
);

SELECT is(
  (SELECT reason_code FROM rotate_encrypted_row(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000002',
    'webhook_endpoints',
    '40000000-0000-0000-0000-000000000002',
    0,
    (SELECT expected_fingerprint FROM rotation_items
     WHERE id = '70000000-0000-0000-0000-000000000002'),
    jsonb_build_object('secret', jsonb_build_object('not', 'ciphertext'))
  )),
  'invalid_payload',
  'authorized malformed JSON value is rejected before any row write'
);
SELECT is(
  (SELECT reason_code FROM rotation_audit_events
   WHERE item_id = '70000000-0000-0000-0000-000000000002'
   ORDER BY created_at DESC LIMIT 1),
  'invalid_payload',
  'invalid payload rejection leaves durable secret-free audit evidence'
);
SELECT is(
  (SELECT reason_code FROM rotate_encrypted_row(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000002',
    'webhook_endpoints',
    '40000000-0000-0000-0000-000000000002',
    0,
    (SELECT expected_fingerprint FROM rotation_items
     WHERE id = '70000000-0000-0000-0000-000000000002'),
    jsonb_build_object('secret', repeat('a', 16385))
  )),
  'invalid_payload',
  'oversized encrypted payload is rejected at the boundary'
);
SELECT is(
  (SELECT reason_code FROM rotate_encrypted_row(
    '50000000-0000-0000-0000-000000000001',
    '70000000-0000-0000-0000-000000000002',
    'webhook_endpoints',
    '40000000-0000-0000-0000-000000000002',
    0,
    (SELECT expected_fingerprint FROM rotation_items
     WHERE id = '70000000-0000-0000-0000-000000000002'),
    jsonb_build_object('secret', 'not-gcm')
  )),
  'invalid_payload',
  'malformed GCM encoding is rejected'
);

DELETE FROM webhook_endpoints
WHERE id = '40000000-0000-0000-0000-000000000002';
SELECT lives_ok(
  $$SELECT 1 FROM rotation_items
    WHERE id = '70000000-0000-0000-0000-000000000002'$$,
  'snapshot item remains after its encrypted row is deleted'
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
  'missing',
  'deleted snapshot row produces a safe missing outcome'
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

-- Explicit mixed CBC ownership is accepted only when every row is bound.
INSERT INTO webhook_endpoints (
  id, account_id, created_by, url, secret
) VALUES
  ('40000000-0000-0000-0000-000000000005',
   '20000000-0000-0000-0000-000000000001',
   '10000000-0000-0000-0000-000000000001',
   'https://rotation.invalid.test/cbc-current',
   repeat('a', 32) || ':' || repeat('b', 32)),
  ('40000000-0000-0000-0000-000000000006',
   '20000000-0000-0000-0000-000000000001',
   '10000000-0000-0000-0000-000000000001',
   'https://rotation.invalid.test/cbc-previous',
   repeat('c', 32) || ':' || repeat('d', 32));
INSERT INTO rotation_runs (
  id, account_id, mode, status, reason_code, current_key_fingerprint,
  previous_key_fingerprint, expected_items
) VALUES (
  '50000000-0000-0000-0000-000000000008',
  '20000000-0000-0000-0000-000000000001',
  'apply', 'awaiting_approval', 'manifest_pending',
  '60000000-0000-0000-0000-000000000001',
  '60000000-0000-0000-0000-000000000002', 2
);
INSERT INTO rotation_items (
  id, run_id, sequence, account_id, table_name, row_id, target_paths,
  expected_version, expected_fingerprint
)
SELECT
  CASE endpoint.id
    WHEN '40000000-0000-0000-0000-000000000005'::UUID
      THEN '70000000-0000-0000-0000-000000000005'::UUID
    ELSE '70000000-0000-0000-0000-000000000006'::UUID
  END,
  '50000000-0000-0000-0000-000000000008',
  row_number() OVER (ORDER BY endpoint.id), endpoint.account_id,
  'webhook_endpoints', endpoint.id, ARRAY['secret'],
  endpoint.secret_version, endpoint.secret_fingerprint
FROM webhook_endpoints AS endpoint
WHERE endpoint.id IN (
  '40000000-0000-0000-0000-000000000005',
  '40000000-0000-0000-0000-000000000006'
);
WITH manifest AS (
  INSERT INTO rotation_manifests (
    run_id, revision, preparer_id, manifest_digest, entry_count
  ) VALUES (
    '50000000-0000-0000-0000-000000000008', 1,
    '10000000-0000-0000-0000-000000000001',
    extensions.digest(convert_to('mixed-cbc', 'UTF8'), 'sha256'), 2
  ) RETURNING id, manifest_digest
)
INSERT INTO rotation_manifest_entries (
  manifest_id, run_id, account_id, table_name, row_id, value_path,
  value_format, legacy_owner, value_digest
)
SELECT
  manifest.id, '50000000-0000-0000-0000-000000000008',
  endpoint.account_id, 'webhook_endpoints', endpoint.id, 'secret', 'cbc',
  CASE endpoint.id
    WHEN '40000000-0000-0000-0000-000000000005'::UUID THEN 'current'
    ELSE 'previous'
  END,
  extensions.digest(convert_to(endpoint.secret, 'UTF8'), 'sha256')
FROM manifest
CROSS JOIN webhook_endpoints AS endpoint
WHERE endpoint.id IN (
  '40000000-0000-0000-0000-000000000005',
  '40000000-0000-0000-0000-000000000006'
);
SELECT is(
  (SELECT outcome FROM approve_rotation_manifest(
    '50000000-0000-0000-0000-000000000008',
    encode(extensions.digest(convert_to('mixed-cbc', 'UTF8'), 'sha256'), 'hex'),
    'approved'
  )),
  'approved',
  'row-scoped current and previous CBC ownership can coexist safely'
);

-- Third remediation — mode safety, recoverable gates, public zero inventory,
-- effective monitoring roles, and write-barrier triggers.
SELECT set_config(
  'request.jwt.claims',
  '{"role":"service_role","sub":"10000000-0000-0000-0000-000000000002"}',
  TRUE
);
CREATE TEMP TABLE read_only_run AS
SELECT prepare_key_rotation_run(
  '20000000-0000-0000-0000-000000000001', 'dry_run',
  '60000000-0000-0000-0000-000000000001',
  '60000000-0000-0000-0000-000000000002'
) AS run_id;
SELECT * FROM start_key_rotation_run((SELECT run_id FROM read_only_run));
CREATE TEMP TABLE read_only_version AS
SELECT secret_version
FROM whatsapp_config
WHERE id = '40000000-0000-0000-0000-000000000001';
SELECT is(
  (SELECT reason_code FROM rotate_encrypted_row(
    (SELECT run_id FROM read_only_run),
    (SELECT id FROM rotation_items
     WHERE run_id = (SELECT run_id FROM read_only_run)
       AND table_name = 'whatsapp_config' LIMIT 1),
    'whatsapp_config', '40000000-0000-0000-0000-000000000001',
    (SELECT expected_version FROM rotation_items
     WHERE run_id = (SELECT run_id FROM read_only_run)
       AND table_name = 'whatsapp_config' LIMIT 1),
    (SELECT expected_fingerprint FROM rotation_items
     WHERE run_id = (SELECT run_id FROM read_only_run)
       AND table_name = 'whatsapp_config' LIMIT 1),
    '{}'::jsonb
  )),
  'mode_read_only',
  'dry-run mode rejects the mutating row RPC'
);
SELECT is(
  (SELECT secret_version FROM whatsapp_config
   WHERE id = '40000000-0000-0000-0000-000000000001'),
  (SELECT secret_version FROM read_only_version),
  'dry-run rejection performs no encrypted table update'
);

CREATE TEMP TABLE recovery_run AS
SELECT prepare_key_rotation_run(
  '20000000-0000-0000-0000-000000000001', 'dry_run',
  '60000000-0000-0000-0000-000000000001',
  '60000000-0000-0000-0000-000000000002'
) AS run_id;
SELECT * FROM start_key_rotation_run((SELECT run_id FROM recovery_run));
UPDATE whatsapp_config
SET access_token = repeat('9', 24) || ':' || repeat('8', 32) || ':' || repeat('7', 32)
WHERE id = '40000000-0000-0000-0000-000000000001';
SELECT is(
  (SELECT reason_code FROM finalize_key_rotation_run(
    (SELECT run_id FROM recovery_run)
  )),
  'inventory_changed',
  'early finalization reports changed inventory'
);
SELECT is(
  (SELECT status FROM get_key_rotation_status((SELECT run_id FROM recovery_run))),
  'running',
  'early finalization remains recoverable in running state'
);

CREATE TEMP TABLE zero_inventory_run AS
SELECT prepare_key_rotation_run(
  '20000000-0000-0000-0000-000000000002', 'final_audit',
  '60000000-0000-0000-0000-000000000001', NULL
) AS run_id;
SELECT is(
  (SELECT outcome FROM start_key_rotation_run(
    (SELECT run_id FROM zero_inventory_run)
  )),
  'started',
  'zero-inventory final audit starts through the public RPC'
);
SELECT is(
  (SELECT outcome FROM finalize_key_rotation_run(
    (SELECT run_id FROM zero_inventory_run)
  )),
  'completed',
  'zero-inventory final audit finalizes through the public RPC'
);
SELECT ok(
  (SELECT status = 'completed' AND expected_items = 0
   FROM get_key_rotation_status((SELECT run_id FROM zero_inventory_run))),
  'zero-inventory status is complete without direct evidence inserts'
);

SELECT ok(
  (SELECT is_stuck FROM list_active_key_rotation_runs(INTERVAL '1 microsecond')
   WHERE run_id = (SELECT run_id FROM recovery_run)),
  'monitoring discovers a stuck recoverable run'
);
SELECT ok(
  (SELECT error_events > 0 AND error_rate > 0
   FROM get_key_rotation_audit_summary((SELECT run_id FROM recovery_run))),
  'monitoring exposes aggregate gate error signals'
);
SELECT ok(
  has_function_privilege(
    'service_role', 'public.list_active_key_rotation_runs(interval)', 'EXECUTE'
  ),
  'service role can discover active and stuck runs'
);
SELECT ok(
  NOT has_function_privilege(
    'authenticated', 'public.get_key_rotation_audit_summary(uuid)', 'EXECUTE'
  ),
  'authenticated callers cannot read aggregate operational monitoring'
);
SELECT has_trigger(
  'public', 'whatsapp_config', 'whatsapp_config_secret_metadata',
  'WhatsApp writes participate in the secret barrier'
);
SELECT has_trigger(
  'public', 'salesforce_config', 'salesforce_config_secret_metadata',
  'Salesforce writes participate in the secret barrier'
);
SELECT has_trigger(
  'public', 'ai_configs', 'ai_configs_secret_metadata',
  'AI writes participate in the secret barrier'
);
SELECT has_trigger(
  'public', 'webhook_endpoints', 'webhook_endpoints_secret_metadata',
  'webhook writes participate in the secret barrier'
);

-- Complete executable lifecycle, monitoring, retention, purge, and replay.
INSERT INTO rotation_runs (
  id, account_id, mode, status, reason_code, current_key_fingerprint,
  previous_key_fingerprint, expected_items, visited_items, terminal_items,
  started_at
) VALUES (
  '50000000-0000-0000-0000-000000000009',
  '20000000-0000-0000-0000-000000000002',
  'final_audit', 'running', 'started',
  '60000000-0000-0000-0000-000000000001',
  '60000000-0000-0000-0000-000000000002',
  0, 0, 0, now()
);
WITH manifest AS (
  INSERT INTO rotation_manifests (
    run_id, revision, preparer_id, manifest_digest, entry_count
  ) VALUES (
    '50000000-0000-0000-0000-000000000009', 1,
    '10000000-0000-0000-0000-000000000001',
    extensions.digest(convert_to('lifecycle', 'UTF8'), 'sha256'), 1
  ) RETURNING id, run_id, manifest_digest
)
INSERT INTO rotation_manifest_approvals (
  manifest_id, run_id, manifest_digest, decision, approver_id
)
SELECT id, run_id, manifest_digest, 'approved',
  '10000000-0000-0000-0000-000000000002'
FROM manifest;

SELECT set_config(
  'request.jwt.claims',
  '{"role":"service_role","sub":"10000000-0000-0000-0000-000000000002"}',
  TRUE
);
SELECT is(
  (SELECT outcome FROM finalize_key_rotation_run(
    '50000000-0000-0000-0000-000000000009'
  )),
  'completed',
  'finalization atomically reconciles expected, visited, and terminal counts'
);
SELECT is(
  (SELECT status FROM get_key_rotation_status(
    '50000000-0000-0000-0000-000000000009'
  )),
  'completed',
  'monitoring reads secret-safe aggregate status without table grants'
);
SELECT disable_key_rotation_operations('maintenance');
SELECT is(
  (SELECT outcome FROM confirm_previous_key_retirement(
    '50000000-0000-0000-0000-000000000009'
  )),
  'retired',
  'completed gate starts previous-key retirement retention'
);
SELECT is(
  (SELECT reason_code FROM purge_rotation_evidence(
    '50000000-0000-0000-0000-000000000009'
  )),
  'retention_active',
  'purge is blocked immediately after retirement'
);
UPDATE rotation_runs
SET previous_key_retired_at = now() - INTERVAL '89 days',
    purge_after = now() + INTERVAL '1 day'
WHERE id = '50000000-0000-0000-0000-000000000009';
SELECT is(
  (SELECT reason_code FROM purge_rotation_evidence(
    '50000000-0000-0000-0000-000000000009'
  )),
  'retention_active',
  'day-89 purge remains blocked'
);
UPDATE rotation_runs
SET previous_key_retired_at = now() - INTERVAL '90 days',
    purge_after = now()
WHERE id = '50000000-0000-0000-0000-000000000009';
SELECT is(
  (SELECT outcome FROM purge_rotation_evidence(
    '50000000-0000-0000-0000-000000000009'
  )),
  'purged',
  'day-90 purge removes row-level evidence'
);
SELECT is(
  (SELECT outcome FROM purge_rotation_evidence(
    '50000000-0000-0000-0000-000000000009'
  )),
  'already_purged',
  'purge replay is idempotent'
);

SELECT * FROM finish();
ROLLBACK;
