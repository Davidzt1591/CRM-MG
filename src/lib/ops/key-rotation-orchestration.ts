import type { SupabaseClient } from '@supabase/supabase-js';

/**
 * Typed application orchestration for the key-rotation lifecycle RPCs
 * implemented by the DB contract (migration 046).
 *
 * Contract:
 * - Every lifecycle call is scoped by `account_id` (account barrier) and
 *   `run_id`; the client never reads or writes the encrypted tables directly.
 * - `prepare_key_rotation_run` opens a run for the account, `start_key_rotation_run`
 *   activates it, and `key_rotation_inventory` returns the per-account values
 *   to rotate.
 * - `rotate_encrypted_row` performs a compare-and-swap rotation and is
 *   service-role only: key material never leaves the database. The client
 *   passes the current ciphertext as `expected_ciphertext` and receives
 *   `rotated: false` with a `reason` on a CAS miss or an account-barrier
 *   violation.
 * - The retirement gate is enforced before the previous key is retired:
 *   `finalize_key_rotation_run` reports whether every row is current
 *   (`all_current`) and how long the previous key has served
 *   (`previous_key_age_days`). Retirement is refused unless all rows are
 *   current AND the previous key has reached the retention window
 *   (`retention_days`, 90 by contract). Only a passing gate leads to
 *   `confirm_key_rotation_run`, then `purge_key_rotation_run` and
 *   `disable_key_rotation_run`.
 */

export type InventoryItem = {
  table: string;
  column: string;
  jsonKey?: string;
  rowId: string;
  ciphertext: string;
};

export type RetirementGate = {
  allCurrent: boolean;
  previousKeyAgeDays: number;
  retentionDays: number;
  passes: boolean;
};

export type RotationRunResult = {
  runId: string;
  planned: number;
  rotated: number;
  conflicts: number;
  gate: RetirementGate;
  confirmed: boolean;
};

export type RotationOrchestrationOptions = {
  /** Account the run is scoped to (account barrier). */
  accountId: string;
  report?: (message: string) => void;
};

export class KeyRotationBarrierError extends Error {
  constructor(rowId: string, runId: string) {
    super(
      `Key rotation barrier conflict: row ${rowId} is outside the account scope of run ${runId}`
    );
    this.name = 'KeyRotationBarrierError';
  }
}

export class KeyRotationGateError extends Error {
  readonly gate: RetirementGate;

  constructor(gate: RetirementGate) {
    const blockers: string[] = [];
    if (!gate.allCurrent) blockers.push('not all rows are current');
    if (gate.previousKeyAgeDays < gate.retentionDays) {
      blockers.push(
        `previous key is ${gate.previousKeyAgeDays}d old (retention ${gate.retentionDays}d)`
      );
    }
    super(`Key rotation retirement gate failed: ${blockers.join('; ')}`);
    this.name = 'KeyRotationGateError';
    this.gate = gate;
  }
}

const RPC = {
  prepare: 'prepare_key_rotation_run',
  start: 'start_key_rotation_run',
  inventory: 'key_rotation_inventory',
  rotate: 'rotate_encrypted_row',
  finalize: 'finalize_key_rotation_run',
  confirm: 'confirm_key_rotation_run',
  purge: 'purge_key_rotation_run',
  disable: 'disable_key_rotation_run',
} as const;

type AccountScope = { account_id: string };
type RunScope = AccountScope & { run_id: string };

type RpcEnvelope<T> = {
  data: T | null;
  error: { message: string } | null;
};

async function callRpc<T>(
  client: SupabaseClient,
  name: string,
  params: object
): Promise<T> {
  const { data, error } = (await client.rpc(
    name,
    params
  )) as unknown as RpcEnvelope<T>;
  if (error) {
    throw new Error(`Key rotation RPC ${name} failed: ${error.message}`);
  }
  if (data === null || data === undefined) {
    throw new Error(`Key rotation RPC ${name} returned no data`);
  }
  return data;
}

export async function orchestrateKeyRotation(
  client: SupabaseClient,
  options: RotationOrchestrationOptions
): Promise<RotationRunResult> {
  const report = options.report ?? console.log;
  const accountScope: AccountScope = { account_id: options.accountId };

  // 1. Open a run for this account (account barrier).
  const prepared = await callRpc<{ run_id: string }>(
    client,
    RPC.prepare,
    accountScope
  );
  const runId = prepared.run_id;
  const runScope: RunScope = { ...accountScope, run_id: runId };

  // 2. Activate the run.
  await callRpc<{ ok: boolean }>(client, RPC.start, runScope);

  // 3. Traverse the per-account inventory of values to rotate.
  const inventory = await callRpc<InventoryItem[]>(
    client,
    RPC.inventory,
    runScope
  );

  // 4. Rotate each item under the account barrier via the service-role CAS RPC.
  let rotated = 0;
  let conflicts = 0;
  for (const item of inventory) {
    const outcome = await callRpc<{ rotated: boolean; reason?: string }>(
      client,
      RPC.rotate,
      {
        ...runScope,
        table: item.table,
        column: item.column,
        ...(item.jsonKey !== undefined ? { json_key: item.jsonKey } : {}),
        row_id: item.rowId,
        expected_ciphertext: item.ciphertext,
      }
    );
    if (outcome.reason === 'account_barrier') {
      throw new KeyRotationBarrierError(item.rowId, runId);
    }
    if (outcome.rotated) {
      rotated += 1;
    } else {
      conflicts += 1;
      report(
        `[conflict] ${item.table}.${item.column} row ${item.rowId} (CAS miss)`
      );
    }
  }

  // 5. Finalize: the DB reports the retirement gate (all-current + retention).
  const finalized = await callRpc<{
    all_current: boolean;
    previous_key_age_days: number;
    retention_days: number;
  }>(client, RPC.finalize, runScope);
  const gate: RetirementGate = {
    allCurrent: finalized.all_current,
    previousKeyAgeDays: finalized.previous_key_age_days,
    retentionDays: finalized.retention_days,
    passes:
      finalized.all_current &&
      finalized.previous_key_age_days >= finalized.retention_days,
  };

  // 6. Retirement gate: never retire the previous key unless every row is
  //    current AND the previous key has served its retention window.
  if (!gate.passes) {
    throw new KeyRotationGateError(gate);
  }

  // 7. Confirm retirement, then purge and disable the old key material.
  await callRpc<{ confirmed: boolean }>(client, RPC.confirm, runScope);
  await callRpc<{ ok: boolean }>(client, RPC.purge, runScope);
  await callRpc<{ ok: boolean }>(client, RPC.disable, runScope);

  report(
    `[confirmed] run ${runId} for account ${options.accountId}: ${rotated} rotated, ${conflicts} conflicts`
  );

  return {
    runId,
    planned: inventory.length,
    rotated,
    conflicts,
    gate,
    confirmed: true,
  };
}
