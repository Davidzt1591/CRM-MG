import type { SupabaseClient } from '@supabase/supabase-js';
import { reEncrypt } from '../whatsapp/encryption.ts';

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
  report?: (message: string) => void;
};

export function shouldApplyRotation(args: readonly string[]): boolean {
  return args.includes('--apply');
}

function encryptedValues(
  row: Record<string, unknown>,
  entry: InventoryEntry
): Array<{ key?: string; value: string }> {
  const stored = row[entry.column];
  if (entry.jsonKeys) {
    if (!stored || typeof stored !== 'object' || Array.isArray(stored))
      return [];
    const json = stored as Record<string, unknown>;
    return entry.jsonKeys.flatMap((key) =>
      typeof json[key] === 'string' ? [{ key, value: json[key] }] : []
    );
  }
  return typeof stored === 'string' ? [{ value: stored }] : [];
}

export async function rotateEncryptedColumns(
  client: SupabaseClient,
  options: RotationOptions
): Promise<RotationSummary> {
  const report = options.report ?? console.log;
  const summary: RotationSummary = { planned: 0, rotated: 0, skipped: 0 };

  for (const entry of ENCRYPTED_COLUMN_INVENTORY) {
    const { data, error } = await client
      .from(entry.table)
      .select(`id,${entry.column}`);
    if (error)
      throw new Error(
        `Failed to read ${entry.table}.${entry.column}: ${error.message}`
      );

    for (const rawRow of data ?? []) {
      const row = rawRow as Record<string, unknown> & { id: string };
      const values = encryptedValues(row, entry);
      if (values.length === 0) continue;
      summary.planned += values.length;

      try {
        const rotated = values.map(({ key, value }) => ({
          key,
          value: reEncrypt(value),
        }));
        if (!options.apply) {
          report(`[dry-run] ${entry.table}.${entry.column} row ${row.id}`);
          continue;
        }

        let replacement: unknown = rotated[0].value;
        if ('jsonKeys' in entry) {
          replacement = { ...(row[entry.column] as Record<string, unknown>) };
          for (const value of rotated) {
            (replacement as Record<string, unknown>)[value.key!] = value.value;
          }
        }

        const { error: updateError } = await client
          .from(entry.table)
          .update({ [entry.column]: replacement })
          .eq('id', row.id);
        if (updateError) throw updateError;

        summary.rotated += values.length;
        report(`[rotated] ${entry.table}.${entry.column} row ${row.id}`);
      } catch (error) {
        summary.skipped += values.length;
        const message = error instanceof Error ? error.message : String(error);
        report(
          `[skipped] ${entry.table}.${entry.column} row ${row.id}: ${message}`
        );
      }
    }
  }

  return summary;
}
