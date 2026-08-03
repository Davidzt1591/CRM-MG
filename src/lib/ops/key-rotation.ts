import type { SupabaseClient } from '@supabase/supabase-js';
import { reEncrypt, type LegacyKeyOwnership } from '../whatsapp/encryption';

type InventoryEntry = {
  table: string;
  column: string;
  jsonKeys?: readonly string[];
};

export const ENCRYPTED_COLUMN_INVENTORY = [
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
] as const satisfies readonly InventoryEntry[];

export type RotationSummary = {
  planned: number;
  rotated: number;
  skipped: number;
};

type RotationOptions = {
  apply: boolean;
  legacyCbcKey?: LegacyKeyOwnership;
  pageSize?: number;
  report?: (message: string) => void;
};

type ExtractedTargets = {
  malformed: string[];
  values: Array<{ key?: string; value: string }>;
};

const DEFAULT_PAGE_SIZE = 500;

function extractTargets(
  row: Record<string, unknown>,
  entry: InventoryEntry
): ExtractedTargets {
  const stored = row[entry.column];
  if (stored === null || stored === undefined) {
    return { malformed: [], values: [] };
  }

  if (!entry.jsonKeys) {
    return typeof stored === 'string'
      ? { malformed: [], values: [{ value: stored }] }
      : { malformed: [entry.column], values: [] };
  }

  if (typeof stored !== 'object' || Array.isArray(stored)) {
    return { malformed: [...entry.jsonKeys], values: [] };
  }

  const json = stored as Record<string, unknown>;
  const result: ExtractedTargets = { malformed: [], values: [] };
  for (const key of entry.jsonKeys) {
    if (!Object.hasOwn(json, key)) continue;
    if (typeof json[key] === 'string') {
      result.values.push({ key, value: json[key] });
    } else {
      result.malformed.push(key);
    }
  }
  return result;
}

export async function rotateEncryptedColumns(
  client: SupabaseClient,
  options: RotationOptions
): Promise<RotationSummary> {
  const report = options.report ?? console.log;
  const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
  const summary: RotationSummary = { planned: 0, rotated: 0, skipped: 0 };

  for (const entry of ENCRYPTED_COLUMN_INVENTORY) {
    let expectedCount: number | undefined;
    let offset = 0;

    do {
      const { data, count, error } = await client
        .from(entry.table)
        .select(`id,${entry.column}`, { count: 'exact' })
        .order('id', { ascending: true })
        .range(offset, offset + pageSize - 1);

      if (error) {
        throw new Error(
          `Failed to select ${entry.table}.${entry.column}: ${error.message}`
        );
      }
      if (count === null || count === undefined) {
        throw new Error(
          `Incomplete traversal for ${entry.table}.${entry.column}: exact count unavailable`
        );
      }
      if (expectedCount === undefined) expectedCount = count;
      if (count !== expectedCount) {
        throw new Error(
          `Incomplete traversal for ${entry.table}.${entry.column}: row count changed`
        );
      }
      if ((!data || data.length === 0) && offset < expectedCount) {
        throw new Error(
          `Incomplete traversal for ${entry.table}.${entry.column}: stopped at ${offset} of ${expectedCount}`
        );
      }

      for (const rawRow of data ?? []) {
        const row = rawRow as Record<string, unknown> & { id: string };
        const targets = extractTargets(row, entry);
        const targetCount = targets.values.length + targets.malformed.length;
        if (targetCount === 0) continue;
        summary.planned += targetCount;

        if (targets.malformed.length > 0) {
          summary.skipped += targetCount;
          report(
            `[skipped] ${entry.table}.${entry.column} row ${row.id}: malformed ${targets.malformed.join(', ')}`
          );
          continue;
        }

        try {
          const rotated = targets.values.map(({ key, value }) => ({
            key,
            value: reEncrypt(value, { legacyKey: options.legacyCbcKey }),
          }));
          if (!options.apply) {
            report(`[dry-run] ${entry.table}.${entry.column} row ${row.id}`);
            continue;
          }

          const original = row[entry.column];
          let replacement: unknown = rotated[0].value;
          if ('jsonKeys' in entry) {
            replacement = { ...(original as Record<string, unknown>) };
            for (const value of rotated) {
              (replacement as Record<string, unknown>)[value.key!] =
                value.value;
            }
          }

          const { data: updated, error: updateError } = await client
            .from(entry.table)
            .update({ [entry.column]: replacement })
            .eq('id', row.id)
            .eq(entry.column, original)
            .select('id');
          if (updateError) throw updateError;
          if (!updated || updated.length !== 1) {
            throw new Error('concurrent update conflict');
          }

          summary.rotated += targets.values.length;
          report(`[rotated] ${entry.table}.${entry.column} row ${row.id}`);
        } catch (error) {
          summary.skipped += targets.values.length;
          const message =
            error instanceof Error ? error.message : String(error);
          report(
            `[skipped] ${entry.table}.${entry.column} row ${row.id}: ${message}`
          );
        }
      }

      offset += data?.length ?? 0;
      if (offset > expectedCount) {
        throw new Error(
          `Incomplete traversal for ${entry.table}.${entry.column}: received duplicate rows`
        );
      }
    } while (offset < expectedCount);
  }

  return summary;
}
