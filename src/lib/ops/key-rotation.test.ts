import type { SupabaseClient } from '@supabase/supabase-js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const CURRENT_KEY = 'a'.repeat(64);
const PREVIOUS_KEY = 'b'.repeat(64);

type Row = Record<string, unknown> & { id: string };

function createFakeClient(seed: Record<string, Row[]>) {
  const tables = structuredClone(seed);
  const updates: Array<{ table: string; id: string; values: object }> = [];

  const client = {
    from(table: string) {
      return {
        async select() {
          return { data: tables[table] ?? [], error: null };
        },
        update(values: object) {
          return {
            async eq(_column: string, id: string) {
              const row = tables[table]?.find(
                (candidate) => candidate.id === id
              );
              if (!row) return { error: new Error(`Missing row ${id}`) };
              Object.assign(row, values);
              updates.push({ table, id, values });
              return { error: null };
            },
          };
        },
      };
    },
  } as unknown as SupabaseClient;

  return { client, tables, updates };
}

async function loadModule() {
  return import('./key-rotation');
}

describe('key rotation operations', () => {
  beforeEach(() => {
    process.env.ENCRYPTION_KEY = CURRENT_KEY;
    delete process.env.ENCRYPTION_KEY_PREVIOUS;
    vi.resetModules();
  });

  afterEach(() => {
    delete process.env.ENCRYPTION_KEY_PREVIOUS;
  });

  it('defaults to dry-run and requires an explicit --apply flag', async () => {
    const { shouldApplyRotation } = await loadModule();

    expect(shouldApplyRotation([])).toBe(false);
    expect(shouldApplyRotation(['--dry-run'])).toBe(false);
    expect(shouldApplyRotation(['--apply'])).toBe(true);
  });

  it('inventories every specified encrypted field including the Salesforce webhook secret', async () => {
    const { ENCRYPTED_COLUMN_INVENTORY } = await loadModule();

    expect(ENCRYPTED_COLUMN_INVENTORY).toEqual([
      { table: 'whatsapp_config', column: 'access_token' },
      { table: 'whatsapp_config', column: 'verify_token' },
      {
        table: 'whatsapp_config',
        column: 'provider_config',
        jsonKeys: ['apiKey', 'secret'],
      },
      { table: 'salesforce_config', column: 'client_id' },
      { table: 'salesforce_config', column: 'client_secret' },
      { table: 'salesforce_config', column: 'username' },
      { table: 'salesforce_config', column: 'password' },
      { table: 'salesforce_config', column: 'security_token' },
      { table: 'salesforce_config', column: 'webhook_secret' },
      { table: 'ai_configs', column: 'api_key' },
      { table: 'ai_configs', column: 'embeddings_api_key' },
      { table: 'webhook_endpoints', column: 'secret' },
    ]);
  });

  it('validates rows in dry-run mode without writing them', async () => {
    const { encrypt } = await import('../whatsapp/encryption');
    const { rotateEncryptedColumns } = await loadModule();
    const fake = createFakeClient({
      whatsapp_config: [{ id: 'wa-1', access_token: encrypt('token') }],
    });

    const summary = await rotateEncryptedColumns(fake.client, { apply: false });

    expect(summary).toEqual({ planned: 1, rotated: 0, skipped: 0 });
    expect(fake.updates).toHaveLength(0);
  });

  it('rotates scalar and JSON secrets while preserving unrelated JSON values', async () => {
    const { decrypt, encrypt } = await import('../whatsapp/encryption');
    const { rotateEncryptedColumns } = await loadModule();
    const fake = createFakeClient({
      whatsapp_config: [
        {
          id: 'wa-1',
          access_token: encrypt('access'),
          verify_token: encrypt('verify'),
          provider_config: {
            apiKey: encrypt('api-key'),
            secret: encrypt('provider-secret'),
            region: 'us',
          },
        },
      ],
      salesforce_config: [
        { id: 'sf-1', webhook_secret: encrypt('webhook-secret') },
      ],
    });

    const summary = await rotateEncryptedColumns(fake.client, { apply: true });

    expect(summary).toEqual({ planned: 5, rotated: 5, skipped: 0 });
    const whatsapp = fake.tables.whatsapp_config[0];
    const provider = whatsapp.provider_config as Record<string, string>;
    expect(decrypt(whatsapp.access_token as string)).toBe('access');
    expect(decrypt(whatsapp.verify_token as string)).toBe('verify');
    expect(decrypt(provider.apiKey)).toBe('api-key');
    expect(decrypt(provider.secret)).toBe('provider-secret');
    expect(provider.region).toBe('us');
    expect(
      decrypt(fake.tables.salesforce_config[0].webhook_secret as string)
    ).toBe('webhook-secret');
  });

  it('reports a corrupt row without preventing later rows from rotating', async () => {
    const { decrypt, encrypt } = await import('../whatsapp/encryption');
    const { rotateEncryptedColumns } = await loadModule();
    const reports: string[] = [];
    const fake = createFakeClient({
      webhook_endpoints: [
        { id: 'bad', secret: 'not-encrypted' },
        { id: 'good', secret: encrypt('healthy') },
      ],
    });

    const summary = await rotateEncryptedColumns(fake.client, {
      apply: true,
      report: (message) => reports.push(message),
    });

    expect(summary).toEqual({ planned: 2, rotated: 1, skipped: 1 });
    expect(reports.some((message) => message.includes('bad'))).toBe(true);
    expect(decrypt(fake.tables.webhook_endpoints[1].secret as string)).toBe(
      'healthy'
    );
  });

  it('rotates previous-key ciphertext and remains safe to run again', async () => {
    process.env.ENCRYPTION_KEY = PREVIOUS_KEY;
    vi.resetModules();
    const previous = await import('../whatsapp/encryption');
    const oldCiphertext = previous.encrypt('rotate-me');

    process.env.ENCRYPTION_KEY = CURRENT_KEY;
    process.env.ENCRYPTION_KEY_PREVIOUS = PREVIOUS_KEY;
    vi.resetModules();
    const { rotateEncryptedColumns } = await loadModule();
    const fake = createFakeClient({
      ai_configs: [{ id: 'ai-1', api_key: oldCiphertext }],
    });

    await rotateEncryptedColumns(fake.client, { apply: true });
    await rotateEncryptedColumns(fake.client, { apply: true });

    delete process.env.ENCRYPTION_KEY_PREVIOUS;
    vi.resetModules();
    const current = await import('../whatsapp/encryption');
    expect(current.decrypt(fake.tables.ai_configs[0].api_key as string)).toBe(
      'rotate-me'
    );
  });
});
