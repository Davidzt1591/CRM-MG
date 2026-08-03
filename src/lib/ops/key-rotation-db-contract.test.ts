import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const migrationPath = join(
  process.cwd(),
  'supabase/migrations/046_key_rotation_ops.sql'
);

function migration(): string {
  return readFileSync(migrationPath, 'utf8');
}

function tableDefinition(sql: string, table: string): string {
  const match = sql.match(
    new RegExp(`CREATE TABLE ${table} \\(([\\s\\S]*?)\\n\\);`, 'i')
  );
  if (!match) throw new Error(`Missing table ${table}`);
  return match[1];
}

describe('046 key rotation database contract — schema foundation', () => {
  it('is expand-only and contains no destructive production rollback', () => {
    const sql = migration();

    expect(sql).not.toMatch(/\bDROP\s+(?:TABLE|COLUMN|TYPE)\b/i);
    expect(sql).not.toMatch(/\bTRUNCATE\b/i);
    expect(sql).toContain('assert_key_rotation_rollback_safe');
    expect(sql).toContain('disable_key_rotation_operations');
  });

  it('creates secret-free run, item, manifest, entry, approval, and audit tables', () => {
    const sql = migration();
    const tables = [
      'rotation_runs',
      'rotation_items',
      'rotation_manifests',
      'rotation_manifest_entries',
      'rotation_manifest_approvals',
      'rotation_audit_events',
    ];

    for (const table of tables) {
      expect(sql).toContain(`CREATE TABLE ${table}`);
      const definition = tableDefinition(sql, table);
      expect(definition).not.toMatch(/\b(?:plaintext|ciphertext|secret_value)\b/i);
    }
  });

  it('adds versions and opaque fingerprints to every encrypted table', () => {
    const sql = migration();
    for (const table of [
      'whatsapp_config',
      'salesforce_config',
      'ai_configs',
      'webhook_endpoints',
    ]) {
      expect(sql).toMatch(
        new RegExp(
          `ALTER TABLE ${table}[\\s\\S]*?secret_version BIGINT NOT NULL DEFAULT 0[\\s\\S]*?secret_fingerprint UUID NOT NULL DEFAULT gen_random_uuid\\(\\)`,
          'i'
        )
      );
      expect(sql).toContain(`CREATE TRIGGER ${table}_secret_metadata`);
    }
  });

  it('defines bounded statuses, reasons, row paths, uniqueness, and useful indexes', () => {
    const sql = migration();

    expect(sql).toContain('rotation_run_status_check');
    expect(sql).toContain('rotation_item_status_check');
    expect(sql).toContain('rotation_reason_code_check');
    expect(sql).toContain('rotation_item_paths_allowed');
    expect(sql).toContain('UNIQUE (run_id, table_name, row_id)');
    expect(sql).toContain('rotation_items_run_sequence_idx');
    expect(sql).toContain('rotation_audit_events_run_created_idx');
  });

  it('starts disabled and binds retention to 90 days after key retirement', () => {
    const sql = migration();

    expect(sql).toContain('operations_enabled BOOLEAN NOT NULL DEFAULT FALSE');
    expect(sql).toContain("INTERVAL '90 days'");
    expect(sql).toContain('previous_key_retired_at');
    expect(sql).toContain('purge_after');
  });

  it('revokes direct access from public API roles', () => {
    const sql = migration();

    expect(sql).toMatch(
      /REVOKE ALL ON (?:TABLE )?rotation_runs[\s\S]*?FROM PUBLIC, anon, authenticated, service_role/i
    );
    expect(sql).toMatch(
      /ALTER TABLE rotation_audit_events ENABLE ROW LEVEL SECURITY/i
    );
  });
});

describe('046 key rotation database contract — atomic rotation RPC', () => {
  it('defines the fixed service-role-only RPC signature and safe return fields', () => {
    const sql = migration();

    expect(sql).toContain('CREATE FUNCTION rotate_encrypted_row(');
    expect(sql).toContain('p_expected_version BIGINT');
    expect(sql).toContain('p_expected_fingerprint UUID');
    expect(sql).toContain('p_values JSONB');
    expect(sql).toMatch(
      /RETURNS TABLE \(\s*outcome TEXT,\s*account_id UUID,\s*new_version BIGINT,\s*new_fingerprint UUID,\s*reason_code TEXT\s*\)/i
    );
    expect(sql).toContain("auth.role() <> 'service_role'");
    expect(sql).toMatch(
      /GRANT EXECUTE ON FUNCTION rotate_encrypted_row[\s\S]*?TO service_role/i
    );
    expect(sql).toMatch(
      /REVOKE ALL ON FUNCTION rotate_encrypted_row[\s\S]*?FROM PUBLIC, anon, authenticated/i
    );
  });

  it('uses a closed table/path allow-list and validates bounded GCM values', () => {
    const sql = migration();

    expect(sql).toContain("CASE p_table");
    expect(sql).toContain("WHEN 'whatsapp_config'");
    expect(sql).toContain("WHEN 'salesforce_config'");
    expect(sql).toContain("WHEN 'ai_configs'");
    expect(sql).toContain("WHEN 'webhook_endpoints'");
    expect(sql).toContain("jsonb_typeof(p_values) <> 'object'");
    expect(sql).toContain('rotation payload keys do not match the manifest item');
    expect(sql).toMatch(/octet_length\([^)]*\) > 16384/);
    expect(sql).toContain("^[0-9a-f]{24}:[0-9a-f]*:[0-9a-f]{32}$");
    expect(sql).not.toMatch(/\bEXECUTE\s+format\s*\(/i);
  });

  it('performs version/fingerprint CAS and preserves unrelated provider JSON', () => {
    const sql = migration();

    expect(sql).toContain('secret_version = p_expected_version');
    expect(sql).toContain('secret_fingerprint = p_expected_fingerprint');
    expect(sql).toContain("v_provider_config,\n          '{apiKey}'");
    expect(sql).toContain("jsonb_set(v_provider_config, '{secret}'");
    expect(sql).toContain('provider_config = v_provider_config');
    expect(sql).not.toMatch(/AND\s+\w+\s*=\s*p_values\s*->>/i);
  });

  it('returns safe replay, conflict, missing, rejected, and applied outcomes', () => {
    const sql = migration();

    for (const outcome of [
      'applied',
      'already_applied',
      'conflict',
      'missing',
      'rejected',
    ]) {
      expect(sql).toContain(`'${outcome}'`);
    }
    expect(sql).toContain("v_item_status = 'applied'");
    expect(sql).toContain("'item_replayed', 'accepted', 'already_applied'");
  });

  it('keeps value-bearing data out of audit inserts and error messages', () => {
    const sql = migration();
    const auditInserts = sql.match(
      /INSERT INTO rotation_audit_events[\s\S]*?;/gi
    );

    expect(auditInserts).not.toBeNull();
    for (const statement of auditInserts ?? []) {
      expect(statement).not.toMatch(/p_values|plaintext|ciphertext/i);
    }
    expect(sql).not.toMatch(/RAISE[^;]*(?:p_values|SQLERRM)/i);
  });
});

describe('046 key rotation database contract — dual-control CBC manifests', () => {
  it('defines canonical digest-bound import and approval RPCs', () => {
    const sql = migration();

    expect(sql).toContain('CREATE FUNCTION import_rotation_manifest(');
    expect(sql).toContain('CREATE FUNCTION approve_rotation_manifest(');
    expect(sql).toContain('jsonb_agg(entry ORDER BY');
    expect(sql).toMatch(
      /digest\(\s*convert_to\(v_canonical_entries::TEXT, 'UTF8'\), 'sha256'\s*\)/
    );
    expect(sql).toContain('v_computed_digest IS DISTINCT FROM v_submitted_digest');
    expect(sql).toContain('rotation_manifest_entry_digest_matches');
  });

  it('enforces row/path ownership evidence without storing encrypted values', () => {
    const sql = migration();
    const entryDefinition = tableDefinition(sql, 'rotation_manifest_entries');

    expect(entryDefinition).toContain('value_path TEXT NOT NULL');
    expect(entryDefinition).toContain('value_format TEXT NOT NULL');
    expect(entryDefinition).toContain('legacy_owner TEXT NOT NULL');
    expect(entryDefinition).toContain('value_digest BYTEA NOT NULL');
    expect(entryDefinition).not.toMatch(/plaintext|ciphertext|encrypted_value/i);
    expect(sql).toContain("legacy_owner = 'unknown'");
    expect(sql).toMatch(
      /legacy_owner\s+NOT IN\s*\('current', 'previous'\)/
    );
  });

  it('requires separate authorized preparer and approver identities', () => {
    const sql = migration();

    expect(sql).toContain("account_role IN ('owner', 'admin')");
    expect(sql).toContain('v_preparer_id = v_approver_id');
    expect(sql).toContain("'role_collision'::TEXT");
    expect(sql).toContain('rotation_manifest_approvals');
  });

  it('invalidates prior approval by requiring the latest manifest revision', () => {
    const sql = migration();

    expect(sql).toContain('ORDER BY revision DESC');
    expect(sql).toContain("status = 'awaiting_approval'");
    expect(sql).toContain("THEN 'manifest_reimported'");
    expect(sql).toContain('rotation_item_has_approved_manifest');
    expect(sql).toContain('IF NOT rotation_item_has_approved_manifest');
  });

  it('makes manifest and approval evidence immutable outside authorized retention purge', () => {
    const sql = migration();

    expect(sql).toContain('CREATE FUNCTION reject_rotation_evidence_mutation()');
    for (const table of [
      'rotation_manifests',
      'rotation_manifest_entries',
      'rotation_manifest_approvals',
    ]) {
      expect(sql).toContain(`CREATE TRIGGER ${table}_immutable`);
    }
    expect(sql).toContain("current_setting('app.key_rotation_purge', TRUE)");
  });
});
