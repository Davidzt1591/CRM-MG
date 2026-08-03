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
