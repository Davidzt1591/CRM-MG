import type { SupabaseClient } from '@supabase/supabase-js';
import { describe, expect, it } from 'vitest';

/**
 * Deterministic dummy secrets in the documented ciphertext shape
 * (`24-byte` + `32-byte` + `32-byte` colon-delimited). The client never
 * touches key material — `rotate_encrypted_row` is service-role only — so
 * these values are opaque and only used for CAS passthrough assertions.
 */
function dummySecret(seed: number): string {
  return `${String(seed).padStart(24, '0')}:${'b'.repeat(32)}:${'c'.repeat(32)}`;
}

type InventoryItem = {
  table: string;
  column: string;
  jsonKey?: string;
  rowId: string;
  ciphertext: string;
};

type SeedGate = {
  all_current: boolean;
  previous_key_age_days: number;
  retention_days: number;
};

type RpcCall = { name: string; params: Record<string, unknown> };

type FakeOptions = {
  inventory?: InventoryItem[];
  gate?: SeedGate;
  barrierConflictIds?: string[];
  casConflictIds?: string[];
  failRpc?: string;
};

function createFakeClient(options: FakeOptions = {}) {
  const rpcCalls: RpcCall[] = [];
  const gate = options.gate ?? {
    all_current: true,
    previous_key_age_days: 120,
    retention_days: 90,
  };

  const client = {
    from(table: string) {
      throw new Error(`direct table access must be unreachable: ${table}`);
    },
    async rpc(name: string, params: Record<string, unknown>) {
      rpcCalls.push({ name, params });
      if (options.failRpc === name) {
        return { data: null, error: new Error('rpc exploded') };
      }
      switch (name) {
        case 'prepare_key_rotation_run':
          return { data: { run_id: 'run-1' }, error: null };
        case 'start_key_rotation_run':
          return { data: { ok: true }, error: null };
        case 'key_rotation_inventory':
          return { data: options.inventory ?? [], error: null };
        case 'rotate_encrypted_row': {
          const rowId = String(params.row_id);
          if (options.barrierConflictIds?.includes(rowId)) {
            return {
              data: { rotated: false, reason: 'account_barrier' },
              error: null,
            };
          }
          if (options.casConflictIds?.includes(rowId)) {
            return { data: { rotated: false, reason: 'cas_conflict' }, error: null };
          }
          return { data: { rotated: true }, error: null };
        }
        case 'finalize_key_rotation_run':
          return { data: gate, error: null };
        case 'confirm_key_rotation_run':
          return { data: { confirmed: true }, error: null };
        case 'purge_key_rotation_run':
          return { data: { ok: true }, error: null };
        case 'disable_key_rotation_run':
          return { data: { ok: true }, error: null };
        default:
          return { data: null, error: new Error(`unknown rpc ${name}`) };
      }
    },
  } as unknown as SupabaseClient;

  return { client, rpcCalls };
}

async function loadModule() {
  return import('./key-rotation-orchestration');
}

describe('key rotation orchestration (lifecycle RPCs)', () => {
  it('drives prepare → start → rotate per item under the account barrier, then confirms a passing retirement gate', async () => {
    const { orchestrateKeyRotation } = await loadModule();
    const inventory: InventoryItem[] = [
      {
        table: 'whatsapp_config',
        column: 'access_token',
        rowId: 'wa-1',
        ciphertext: dummySecret(1),
      },
      {
        table: 'whatsapp_config',
        column: 'provider_config',
        jsonKey: 'apiKey',
        rowId: 'wa-1',
        ciphertext: dummySecret(2),
      },
      {
        table: 'webhook_endpoints',
        column: 'secret',
        rowId: 'hook-9',
        ciphertext: dummySecret(3),
      },
    ];
    const fake = createFakeClient({ inventory });

    const result = await orchestrateKeyRotation(fake.client, {
      accountId: 'acct-1',
    });

    expect(result).toEqual({
      runId: 'run-1',
      planned: 3,
      rotated: 3,
      conflicts: 0,
      gate: {
        allCurrent: true,
        previousKeyAgeDays: 120,
        retentionDays: 90,
        passes: true,
      },
      confirmed: true,
    });

    // Lifecycle order is fixed: prepare, start, inventory, one rotate per
    // inventory item, then the retirement gate RPCs.
    expect(fake.rpcCalls.map((call) => call.name)).toEqual([
      'prepare_key_rotation_run',
      'start_key_rotation_run',
      'key_rotation_inventory',
      'rotate_encrypted_row',
      'rotate_encrypted_row',
      'rotate_encrypted_row',
      'finalize_key_rotation_run',
      'confirm_key_rotation_run',
      'purge_key_rotation_run',
      'disable_key_rotation_run',
    ]);

    // Account barrier: every lifecycle call carries the account id.
    for (const call of fake.rpcCalls) {
      expect(call.params.account_id).toBe('acct-1');
    }

    // CAS contract: the inventory ciphertext is passed through as the
    // expected value; the JSON leaf carries its json_key.
    const rotateCalls = fake.rpcCalls.filter(
      (call) => call.name === 'rotate_encrypted_row'
    );
    expect(rotateCalls.map((call) => call.params.expected_ciphertext)).toEqual([
      dummySecret(1),
      dummySecret(2),
      dummySecret(3),
    ]);
    expect(rotateCalls[1].params.json_key).toBe('apiKey');
  });

  it('fails closed on an account barrier conflict without finalizing or confirming', async () => {
    const { KeyRotationBarrierError, orchestrateKeyRotation } =
      await loadModule();
    const fake = createFakeClient({
      inventory: [
        {
          table: 'salesforce_config',
          column: 'client_secret',
          rowId: 'stolen-row',
          ciphertext: dummySecret(9),
        },
      ],
      barrierConflictIds: ['stolen-row'],
    });

    await expect(
      orchestrateKeyRotation(fake.client, { accountId: 'acct-1' })
    ).rejects.toThrow(KeyRotationBarrierError);

    const names = fake.rpcCalls.map((call) => call.name);
    expect(names).not.toContain('finalize_key_rotation_run');
    expect(names).not.toContain('confirm_key_rotation_run');
  });

  it('counts CAS conflicts as skipped rotations but still completes the run', async () => {
    const { orchestrateKeyRotation } = await loadModule();
    const fake = createFakeClient({
      inventory: [
        {
          table: 'webhook_endpoints',
          column: 'secret',
          rowId: 'contested',
          ciphertext: dummySecret(5),
        },
        {
          table: 'ai_configs',
          column: 'api_key',
          rowId: 'fresh',
          ciphertext: dummySecret(6),
        },
      ],
      casConflictIds: ['contested'],
    });

    const result = await orchestrateKeyRotation(fake.client, {
      accountId: 'acct-1',
    });

    expect(result).toMatchObject({ planned: 2, rotated: 1, conflicts: 1 });
    expect(result.confirmed).toBe(true);
  });

  it('blocks retirement when a non-current row remains after rotation', async () => {
    const { KeyRotationGateError, orchestrateKeyRotation } = await loadModule();
    const fake = createFakeClient({
      inventory: [
        {
          table: 'webhook_endpoints',
          column: 'secret',
          rowId: 'stale',
          ciphertext: dummySecret(4),
        },
      ],
      gate: {
        all_current: false,
        previous_key_age_days: 300,
        retention_days: 90,
      },
    });

    let caught: unknown;
    try {
      await orchestrateKeyRotation(fake.client, { accountId: 'acct-1' });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(KeyRotationGateError);
    const gateError = caught as {
      gate: { passes: boolean; allCurrent: boolean };
    };
    expect(gateError.gate.passes).toBe(false);
    expect(gateError.gate.allCurrent).toBe(false);

    const names = fake.rpcCalls.map((call) => call.name);
    expect(names).toContain('finalize_key_rotation_run');
    expect(names).not.toContain('confirm_key_rotation_run');
    expect(names).not.toContain('purge_key_rotation_run');
    expect(names).not.toContain('disable_key_rotation_run');
  });

  it('enforces the 90-day retention gate before confirming', async () => {
    const { KeyRotationGateError, orchestrateKeyRotation } = await loadModule();
    const fake = createFakeClient({
      inventory: [
        {
          table: 'whatsapp_config',
          column: 'verify_token',
          rowId: 'wa-2',
          ciphertext: dummySecret(7),
        },
      ],
      gate: {
        all_current: true,
        previous_key_age_days: 89,
        retention_days: 90,
      },
    });

    await expect(
      orchestrateKeyRotation(fake.client, { accountId: 'acct-1' })
    ).rejects.toThrow(KeyRotationGateError);

    expect(
      fake.rpcCalls.map((call) => call.name)
    ).not.toContain('confirm_key_rotation_run');
  });

  it('retires the previous key exactly at the 90-day retention boundary', async () => {
    const { orchestrateKeyRotation } = await loadModule();
    const fake = createFakeClient({
      inventory: [
        {
          table: 'salesforce_config',
          column: 'username',
          rowId: 'sf-1',
          ciphertext: dummySecret(8),
        },
      ],
      gate: {
        all_current: true,
        previous_key_age_days: 90,
        retention_days: 90,
      },
    });

    const result = await orchestrateKeyRotation(fake.client, {
      accountId: 'acct-1',
    });

    expect(result.gate.passes).toBe(true);
    expect(result.confirmed).toBe(true);
  });

  it('aborts the run when a lifecycle RPC errors', async () => {
    const { orchestrateKeyRotation } = await loadModule();
    const fake = createFakeClient({ failRpc: 'prepare_key_rotation_run' });

    await expect(
      orchestrateKeyRotation(fake.client, { accountId: 'acct-1' })
    ).rejects.toThrow(/prepare_key_rotation_run/i);
  });
});
