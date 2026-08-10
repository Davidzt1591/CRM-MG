import type { SupabaseClient } from '@supabase/supabase-js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const CURRENT_KEY = 'a'.repeat(64);

type Row = Record<string, unknown> & { id: string };
type FakeOptions = {
  pageCap?: number;
  selectErrorAt?: number;
  updateErrorIds?: string[];
  conflictIds?: string[];
};

function equal(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function createFakeClient(
  seed: Record<string, Row[]>,
  options: FakeOptions = {}
) {
  const tables = structuredClone(seed);
  const updates: Array<{ table: string; id: string; values: object }> = [];
  const ranges: Array<{
    table: string;
    columns: string;
    from: number;
    to: number;
  }> = [];
  let selectCalls = 0;

  const client = {
    from(table: string) {
      return {
        select(columns: string) {
          return {
            order() {
              return {
                async range(from: number, to: number) {
                  selectCalls += 1;
                  ranges.push({ table, columns, from, to });
                  if (selectCalls === options.selectErrorAt) {
                    return {
                      data: null,
                      count: null,
                      error: new Error('select failed'),
                    };
                  }
                  const rows = tables[table] ?? [];
                  const cap = Math.min(
                    to - from + 1,
                    options.pageCap ?? Infinity
                  );
                  return {
                    data: rows.slice(from, from + cap),
                    count: rows.length,
                    error: null,
                  };
                },
              };
            },
          };
        },
        update(values: object) {
          const filters: Array<{ column: string; value: unknown }> = [];
          const builder = {
            eq(column: string, value: unknown) {
              filters.push({ column, value });
              return builder;
            },
            async select() {
              const id = filters.find((filter) => filter.column === 'id')
                ?.value as string;
              if (options.updateErrorIds?.includes(id)) {
                return { data: null, error: new Error('update failed') };
              }
              const row = tables[table]?.find(
                (candidate) => candidate.id === id
              );
              const matches =
                row &&
                !options.conflictIds?.includes(id) &&
                filters.every((filter) =>
                  equal(row[filter.column], filter.value)
                );
              if (!matches) return { data: [], error: null };
              Object.assign(row, values);
              updates.push({ table, id, values });
              return { data: [{ id }], error: null };
            },
          };
          return builder;
        },
      };
    },
  } as unknown as SupabaseClient;

  return { client, ranges, tables, updates };
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

  it('inventories every specified encrypted field', async () => {
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

  it('inventories all 13 encrypted values without mutating in dry-run mode', async () => {
    const { encrypt } = await import('../whatsapp/encryption');
    const { rotateEncryptedColumns } = await loadModule();
    const secret = (name: string) => encrypt(name);
    const fake = createFakeClient({
      whatsapp_config: [
        {
          id: 'wa',
          access_token: secret('access'),
          verify_token: secret('verify'),
          provider_config: {
            apiKey: secret('provider-api'),
            secret: secret('provider-secret'),
            region: 'us',
          },
        },
      ],
      salesforce_config: [
        {
          id: 'sf',
          client_id: secret('client-id'),
          client_secret: secret('client-secret'),
          username: secret('username'),
          password: secret('password'),
          security_token: secret('security-token'),
          webhook_secret: secret('webhook-secret'),
        },
      ],
      ai_configs: [
        {
          id: 'ai',
          api_key: secret('ai-key'),
          embeddings_api_key: secret('embeddings-key'),
        },
      ],
      webhook_endpoints: [{ id: 'hook', secret: secret('hook-secret') }],
    });

    const first = await rotateEncryptedColumns(fake.client, { apply: false });
    const second = await rotateEncryptedColumns(fake.client, { apply: false });

    expect(first).toEqual({ planned: 13, rotated: 0, skipped: 0 });
    expect(second).toEqual(first);
    expect(fake.updates).toHaveLength(0);
  });

  it('rejects direct apply before querying or updating encrypted tables', async () => {
    const { rotateEncryptedColumns } = await loadModule();
    const from = vi.fn(() => {
      throw new Error('direct table access must be unreachable');
    });

    await expect(
      rotateEncryptedColumns({ from } as unknown as SupabaseClient, {
        apply: true,
      })
    ).rejects.toThrow(
      'RPC orchestration not enabled in this slice; direct apply is disabled.'
    );
    expect(from).not.toHaveBeenCalled();
  });

  it('defaults to dry-run behavior without any update', async () => {
    const { encrypt } = await import('../whatsapp/encryption');
    const { rotateEncryptedColumns } = await loadModule();
    const fake = createFakeClient({
      webhook_endpoints: [{ id: 'hook', secret: encrypt('secret') }],
    });

    const summary = await rotateEncryptedColumns(fake.client, { apply: false });

    expect(summary).toEqual({ planned: 1, rotated: 0, skipped: 0 });
    expect(fake.updates).toHaveLength(0);
  });

  it('traverses multiple short PostgREST pages until the exact count is reached', async () => {
    const { encrypt } = await import('../whatsapp/encryption');
    const { rotateEncryptedColumns } = await loadModule();
    const fake = createFakeClient(
      {
        webhook_endpoints: [
          { id: 'a', secret: encrypt('a') },
          { id: 'b', secret: encrypt('b') },
          { id: 'c', secret: encrypt('c') },
        ],
      },
      { pageCap: 1 }
    );

    const summary = await rotateEncryptedColumns(fake.client, {
      apply: false,
      pageSize: 2,
    });

    expect(summary.planned).toBe(3);
    expect(
      fake.ranges.filter((range) => range.table === 'webhook_endpoints')
    ).toEqual([
      { table: 'webhook_endpoints', columns: 'id,secret', from: 0, to: 1 },
      { table: 'webhook_endpoints', columns: 'id,secret', from: 1, to: 2 },
      { table: 'webhook_endpoints', columns: 'id,secret', from: 2, to: 3 },
    ]);
  });

  it('stops exactly at a page boundary without requesting or processing duplicates', async () => {
    const { encrypt } = await import('../whatsapp/encryption');
    const { rotateEncryptedColumns } = await loadModule();
    const fake = createFakeClient({
      ai_configs: [
        { id: 'a', api_key: encrypt('a') },
        { id: 'b', api_key: encrypt('b') },
      ],
    });

    const summary = await rotateEncryptedColumns(fake.client, {
      apply: false,
      pageSize: 2,
    });

    expect(summary).toEqual({ planned: 2, rotated: 0, skipped: 0 });
    expect(fake.updates).toHaveLength(0);
    expect(
      fake.ranges.filter(
        (range) =>
          range.table === 'ai_configs' && range.columns === 'id,api_key'
      )
    ).toEqual([{ table: 'ai_configs', columns: 'id,api_key', from: 0, to: 1 }]);
  });

  it('fails closed when traversal cannot reach the exact count', async () => {
    const { encrypt } = await import('../whatsapp/encryption');
    const { rotateEncryptedColumns } = await loadModule();
    const fake = createFakeClient(
      { webhook_endpoints: [{ id: 'a', secret: encrypt('a') }] },
      { pageCap: 0 }
    );

    await expect(
      rotateEncryptedColumns(fake.client, { apply: false, pageSize: 2 })
    ).rejects.toThrow(/incomplete/i);
  });

  it('fails the traversal on a select error', async () => {
    const { rotateEncryptedColumns } = await loadModule();
    const fake = createFakeClient({}, { selectErrorAt: 1 });

    await expect(
      rotateEncryptedColumns(fake.client, { apply: false })
    ).rejects.toThrow(/select failed/i);
  });

  it('counts present malformed JSON targets as skipped but ignores absent optional targets', async () => {
    const { encrypt } = await import('../whatsapp/encryption');
    const { rotateEncryptedColumns } = await loadModule();
    const fake = createFakeClient({
      whatsapp_config: [
        { id: 'bad-column', provider_config: 'invalid' },
        { id: 'bad-leaf', provider_config: { apiKey: 42, region: 'us' } },
        { id: 'absent', provider_config: { region: 'eu' } },
        { id: 'valid', provider_config: { secret: encrypt('secret') } },
      ],
    });

    const summary = await rotateEncryptedColumns(fake.client, { apply: false });

    expect(summary).toEqual({ planned: 4, rotated: 0, skipped: 3 });
    expect(fake.updates).toHaveLength(0);
  });
});
