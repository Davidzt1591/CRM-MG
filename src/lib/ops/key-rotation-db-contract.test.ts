import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const migrationPath = join(
  process.cwd(),
  'supabase/migrations/046_key_rotation_ops.sql'
);
const workflowPath = join(process.cwd(), '.github/workflows/ci.yml');
const supabaseConfigPath = join(process.cwd(), 'supabase/config.toml');
const concurrencyTestPath = join(
  process.cwd(),
  'supabase/tests/key_rotation_concurrency.test.sql'
);
const pgTapTestPath = join(
  process.cwd(),
  'supabase/tests/key_rotation_ops.test.sql'
);
const contractDocPath = join(process.cwd(), 'docs/key-rotation-db-contract.md');

function migration(): string {
  return readFileSync(migrationPath, 'utf8');
}

function workflow(): string {
  return readFileSync(workflowPath, 'utf8');
}

function functionDefinition(sql: string, name: string): string {
  const match = sql.match(
    new RegExp(`CREATE FUNCTION public\\.${name}\\([\\s\\S]*?\\n\\$\\$;`, 'i')
  );
  if (!match) throw new Error(`Missing function ${name}`);
  return match[0];
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
      expect(definition).not.toMatch(
        /\b(?:plaintext|ciphertext|secret_value)\b/i
      );
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

  it('repairs the Salesforce webhook secret before triggers reference it', () => {
    const sql = migration();
    const repair = sql.indexOf('ADD COLUMN IF NOT EXISTS webhook_secret TEXT');
    const triggerFunction = sql.indexOf(
      'CREATE FUNCTION public.bump_key_rotation_secret_metadata()'
    );

    expect(repair).toBeGreaterThan(-1);
    expect(triggerFunction).toBeGreaterThan(repair);
  });

  it('uses an explicit extensions schema and trusted SECURITY DEFINER search paths', () => {
    const sql = migration();
    const securityDefiners = sql.match(/SECURITY DEFINER[\s\S]*?AS \$\$/g);

    expect(sql).toContain('CREATE SCHEMA IF NOT EXISTS extensions');
    expect(sql).toContain(
      'CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions'
    );
    expect(sql).toContain('extensions.digest(');
    expect(sql).not.toMatch(/(?<!extensions\.)\bdigest\(/);
    expect(sql).toContain('REVOKE CREATE ON SCHEMA public FROM PUBLIC');
    expect(sql).toContain(
      'GRANT USAGE, CREATE ON SCHEMA public TO key_rotation_executor'
    );
    expect(securityDefiners).not.toBeNull();
    for (const definition of securityDefiners ?? []) {
      expect(definition).toContain('SET search_path = pg_catalog, public');
      expect(definition).not.toContain('pg_temp');
    }
  });
});

describe('046 key rotation database contract — atomic rotation RPC', () => {
  it('defines the fixed service-role-only RPC signature and safe return fields', () => {
    const sql = migration();

    expect(sql).toContain('CREATE FUNCTION public.rotate_encrypted_row(');
    expect(sql).toContain('p_expected_version BIGINT');
    expect(sql).toContain('p_expected_fingerprint UUID');
    expect(sql).toContain('p_values JSONB');
    expect(sql).toMatch(
      /RETURNS TABLE \(\s*outcome TEXT,\s*account_id UUID,\s*new_version BIGINT,\s*new_fingerprint UUID,\s*reason_code TEXT\s*\)/i
    );
    expect(sql).toContain("auth.role() IS DISTINCT FROM 'service_role'");
    expect(sql).toMatch(
      /GRANT EXECUTE ON FUNCTION public\.rotate_encrypted_row[\s\S]*?TO service_role/i
    );
    expect(sql).toMatch(
      /REVOKE ALL ON FUNCTION public\.rotate_encrypted_row[\s\S]*?FROM PUBLIC, anon, authenticated/i
    );
  });

  it('uses a closed table/path allow-list and validates bounded GCM values', () => {
    const sql = migration();

    expect(sql).toContain('CASE p_table');
    expect(sql).toContain("WHEN 'whatsapp_config'");
    expect(sql).toContain("WHEN 'salesforce_config'");
    expect(sql).toContain("WHEN 'ai_configs'");
    expect(sql).toContain("WHEN 'webhook_endpoints'");
    expect(sql).toContain("jsonb_typeof(p_values) IS DISTINCT FROM 'object'");
    expect(sql).toContain("v_account_id, 'invalid_payload'");
    expect(sql).toMatch(/octet_length\([^)]*\) > v_max_ciphertext_bytes/);
    expect(sql).toContain('^[0-9a-f]{24}:[0-9a-f]*:[0-9a-f]{32}$');
    expect(sql).not.toMatch(/\bEXECUTE\s+format\s*\(/i);
    expect(sql).toContain(
      'v_max_ciphertext_bytes CONSTANT INTEGER := 16 * 1024'
    );
  });

  it('performs version/fingerprint CAS and derives JSON updates from the locked row', () => {
    const sql = migration();

    expect(sql).toContain('secret_version = p_expected_version');
    expect(sql).toContain('secret_fingerprint = p_expected_fingerprint');
    expect(sql).toContain("COALESCE(w.provider_config, '{}'::JSONB)");
    expect(sql).not.toContain('v_provider_config JSONB');
    expect(sql).not.toMatch(
      /SELECT COALESCE\(w\.provider_config[\s\S]*?UPDATE whatsapp_config/i
    );
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
    expect(sql).toContain('replacement_payload_digest');
    expect(sql).toContain("'payload_mismatch'");
    expect(sql).toMatch(
      /v_item_status = 'applied'[\s\S]*?rotation_item_matches_applied_metadata[\s\S]*?'item_replayed'/i
    );
  });

  it('mutates encrypted rows only for a locked running apply run', () => {
    const fn = functionDefinition(migration(), 'rotate_encrypted_row');

    expect(fn).toMatch(/SELECT run\.status, run\.mode, run\.account_id/i);
    expect(fn).toContain("v_run_mode IS DISTINCT FROM 'apply'");
    expect(fn).toMatch(
      /lock_key_rotation_account\(v_run_account_id\)[\s\S]*?lock_key_rotation_run\(p_run_id\)[\s\S]*?FOR UPDATE OF i/i
    );
  });

  it('keeps value-bearing data out of audit inserts and error messages', () => {
    const sql = migration();
    const auditInserts = sql.match(
      /INSERT INTO (?:public\.)?rotation_audit_events[\s\S]*?;/gi
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

    expect(sql).toContain('CREATE FUNCTION public.import_rotation_manifest(');
    expect(sql).toContain('CREATE FUNCTION public.approve_rotation_manifest(');
    expect(sql).toContain('jsonb_agg(entry ORDER BY');
    expect(sql).toMatch(
      /extensions\.digest\(\s*convert_to\(v_canonical_entries::TEXT, 'UTF8'\), 'sha256'\s*\)/
    );
    expect(sql).toContain(
      'v_computed_digest IS DISTINCT FROM v_submitted_digest'
    );
    expect(sql).toContain('rotation_manifest_entry_digest_matches');
  });

  it('enforces row/path ownership evidence without storing encrypted values', () => {
    const sql = migration();
    const entryDefinition = tableDefinition(sql, 'rotation_manifest_entries');

    expect(entryDefinition).toContain('value_path TEXT NOT NULL');
    expect(entryDefinition).toContain('value_format TEXT NOT NULL');
    expect(entryDefinition).toContain('legacy_owner TEXT NOT NULL');
    expect(entryDefinition).toContain('value_digest BYTEA NOT NULL');
    expect(entryDefinition).not.toMatch(
      /plaintext|ciphertext|encrypted_value/i
    );
    expect(sql).toContain("legacy_owner = 'unknown'");
    expect(sql).toMatch(/legacy_owner\s+NOT IN\s*\('current', 'previous'\)/);
  });

  it('requires separate authorized preparer and approver identities', () => {
    const sql = migration();

    expect(sql).toContain("account_role IN ('owner', 'admin')");
    expect(sql).toContain('v_preparer_id = v_approver_id');
    expect(sql).toContain("'role_collision'::TEXT");
    expect(sql).toContain('rotation_manifest_approvals');
  });

  it('preserves approval on identical retries and invalidates it only for changed evidence', () => {
    const sql = migration();

    expect(sql).toContain('ORDER BY revision DESC');
    expect(sql).toContain("'manifest_replayed'");
    expect(sql).toMatch(
      /manifest_digest = v_computed_digest[\s\S]*?RETURN QUERY SELECT[\s\S]*?v_existing_manifest_id/i
    );
    expect(sql).toContain("status = 'awaiting_approval'");
    expect(sql).toContain("THEN 'manifest_reimported'");
    expect(sql).toContain('rotation_item_has_approved_manifest');
    expect(sql).toContain('IF NOT public.rotation_item_has_approved_manifest');
  });

  it('makes manifest and approval evidence immutable outside authorized retention purge', () => {
    const sql = migration();

    expect(sql).toContain(
      'CREATE FUNCTION public.reject_rotation_evidence_mutation()'
    );
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

describe('046 key rotation database contract — lifecycle and concurrency', () => {
  it('defines the complete service-role lifecycle and monitoring RPCs', () => {
    const sql = migration();

    for (const functionName of [
      'enable_key_rotation_operations',
      'prepare_key_rotation_run',
      'start_key_rotation_run',
      'finalize_key_rotation_run',
      'confirm_previous_key_retirement',
      'purge_rotation_evidence',
      'get_key_rotation_status',
      'list_active_key_rotation_runs',
      'get_key_rotation_audit_summary',
    ]) {
      expect(sql).toContain(`CREATE FUNCTION public.${functionName}(`);
      expect(sql).toMatch(
        new RegExp(
          `GRANT EXECUTE ON FUNCTION public\\.${functionName}[\\s\\S]*?TO service_role`,
          'i'
        )
      );
    }
    expect(sql).toContain("INTERVAL '90 days'");
    expect(sql).toContain('expected_items');
    expect(sql).toContain('visited_items');
    expect(sql).toContain('terminal_items');
  });

  it('uses one documented control-run-item-row lock order for transitions', () => {
    const sql = migration();

    expect(sql).toContain(
      'LOCK ORDER: control -> account barrier -> run -> item -> encrypted row'
    );
    expect(sql).toContain('CREATE FUNCTION public.lock_key_rotation_account(');
    expect(sql).toContain('pg_advisory_xact_lock');
    expect(sql).toContain('CREATE FUNCTION public.lock_key_rotation_control()');
    expect(sql).toContain('CREATE FUNCTION public.lock_key_rotation_run(');
    expect(sql).toContain('PERFORM public.lock_key_rotation_control()');
    expect(sql).toContain('public.lock_key_rotation_run(p_run_id)');
    expect(sql).toMatch(
      /rotate_encrypted_row[\s\S]*?lock_key_rotation_control\(\)[\s\S]*?lock_key_rotation_run\(p_run_id\)[\s\S]*?FOR UPDATE OF i/i
    );
  });

  it('enforces the account barrier on normal secret inserts and changes only', () => {
    const sql = migration();
    const trigger = functionDefinition(
      sql,
      'bump_key_rotation_secret_metadata'
    );

    expect(trigger).toContain("TG_OP = 'INSERT'");
    expect(trigger).toContain(
      'public.lock_key_rotation_account(NEW.account_id)'
    );
    expect(trigger).toMatch(
      /IF encrypted_value_changed THEN[\s\S]*?lock_key_rotation_account/i
    );
    for (const table of [
      'whatsapp_config',
      'salesforce_config',
      'ai_configs',
      'webhook_endpoints',
    ]) {
      expect(sql).toContain(`BEFORE INSERT OR UPDATE ON ${table}`);
    }
  });

  it('reconciles actual inventory under the barrier before finalization and retirement', () => {
    const sql = migration();
    const finalize = functionDefinition(sql, 'finalize_key_rotation_run');
    const retire = functionDefinition(sql, 'confirm_previous_key_retirement');

    expect(sql).toContain('CREATE FUNCTION public.key_rotation_inventory(');
    for (const fn of [finalize, retire]) {
      expect(fn).toContain('public.lock_key_rotation_account(');
      expect(fn).toContain('public.key_rotation_inventory(');
    }
    expect(finalize).not.toContain("SET status = 'blocked'");
    expect(finalize).toContain("v_run.status IS DISTINCT FROM 'running'");
  });

  it('keeps non-apply lifecycle structurally read-only and supports zero inventory', () => {
    const sql = migration();
    const rotate = functionDefinition(sql, 'rotate_encrypted_row');
    const start = functionDefinition(sql, 'start_key_rotation_run');
    const finalize = functionDefinition(sql, 'finalize_key_rotation_run');

    expect(rotate).toContain("v_run_mode IS DISTINCT FROM 'apply'");
    expect(start).toContain("v_mode IN ('dry_run', 'final_audit')");
    expect(finalize).toContain('v_run.expected_items > 0');
    expect(sql).toContain('zero_inventory');
  });

  it('exposes secret-safe stuck-run and aggregate monitoring signals', () => {
    const sql = migration();
    const active = functionDefinition(sql, 'list_active_key_rotation_runs');
    const summary = functionDefinition(sql, 'get_key_rotation_audit_summary');

    expect(active).toContain('lifecycle_age_seconds');
    expect(active).toContain('is_stuck');
    expect(summary).toContain('error_rate');
    expect(summary).toContain('waiting_advisory_locks');
    expect(summary).toContain('pg_catalog.pg_locks');
    expect(summary).not.toMatch(/plaintext|ciphertext|p_values/i);
  });

  it('removes unreachable failed states from bounded lifecycle enums', () => {
    const sql = migration();

    expect(tableDefinition(sql, 'rotation_runs')).not.toMatch(/'failed'/);
    expect(tableDefinition(sql, 'rotation_items')).not.toMatch(/'failed'/);
  });

  it('fails closed for absent or malformed service-role claims', () => {
    const sql = migration();

    expect(sql).not.toContain("auth.role() <> 'service_role'");
    expect(sql).toContain("auth.role() IS DISTINCT FROM 'service_role'");
  });

  it('ships executable concurrent-session tests and DB contract documentation', () => {
    const concurrency = readFileSync(concurrencyTestPath, 'utf8');
    const documentation = readFileSync(contractDocPath, 'utf8');

    for (const scenario of [
      'inventory-vs-insert',
      'finalize-vs-secret-write',
      'retire-vs-secret-write',
      'emergency-disable-vs-rotate',
      'unrelated-jsonb-vs-rotate',
    ]) {
      expect(concurrency).toContain(scenario);
    }
    expect(concurrency).toContain('dblink_send_query');
    expect(concurrency).toContain('dblink_is_busy');
    expect(concurrency).toContain('pg_locks');
    expect(concurrency).toContain('lock_timeout');
    expect(concurrency).not.toContain('pg_sleep');
    expect(documentation).toContain(
      'control → account barrier → run → item → encrypted row'
    );
    expect(documentation).toContain('State machine');
    expect(documentation).toContain('Recovery contract');
  });
});

describe('database contract CI gate', () => {
  it('applies migrations and executes pgTAP plus concurrency tests locally', () => {
    const yaml = workflow();
    const pgTap = readFileSync(pgTapTestPath, 'utf8');
    const concurrency = readFileSync(concurrencyTestPath, 'utf8');
    const plannedAssertions = [pgTap, concurrency].reduce((total, sql) => {
      const plan = sql.match(/SELECT plan\((\d+)\)/);
      return total + Number(plan?.[1] ?? 0);
    }, 0);

    expect(yaml).toContain('name: Database contract (required)');
    expect(yaml).toContain(
      'supabase/setup-cli@3c2f5e2ae34c34e428e8e206e2c4d21fa2d20fbf'
    );
    expect(yaml).toMatch(/version:\s*2\.\d+\.\d+/);
    expect(yaml).toContain('supabase db reset --local --no-seed');
    expect(yaml).toContain('supabase test db --local');
    expect(plannedAssertions).toBe(114);
    expect(yaml).not.toContain('--linked');
    expect(yaml).toContain('supabase stop --no-backup');
  });

  it('uses pinned actions and a Supabase 2.45.4-compatible local config', () => {
    const yaml = workflow();
    const config = readFileSync(supabaseConfigPath, 'utf8');
    const actions = [...yaml.matchAll(/uses:\s*([^\s#]+)/g)].map(
      (match) => match[1]
    );

    expect(actions.length).toBeGreaterThan(0);
    for (const action of actions) {
      expect(action).toMatch(/@[0-9a-f]{40}$/);
    }
    expect(config).toContain('[inbucket]');
    expect(config).not.toContain('[local_smtp]');
    expect(yaml.indexOf('supabase start')).toBeLessThan(
      yaml.indexOf('supabase db reset --local --no-seed')
    );
    expect(yaml.indexOf('supabase db reset --local --no-seed')).toBeLessThan(
      yaml.indexOf('supabase test db --local')
    );
  });
});
