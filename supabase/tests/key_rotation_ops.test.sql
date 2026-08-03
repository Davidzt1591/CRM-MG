BEGIN;

CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA extensions;
SET search_path = public, extensions;

SELECT plan(25);

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

SELECT * FROM finish();
ROLLBACK;
