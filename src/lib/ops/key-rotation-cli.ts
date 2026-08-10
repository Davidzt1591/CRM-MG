import type { SupabaseClient } from '@supabase/supabase-js';
import type { LegacyKeyOwnership } from '../whatsapp/encryption';
import type { RotationSummary } from './key-rotation';

type Environment = Record<string, string | undefined>;
type CliOptions = {
  apply: boolean;
  help: boolean;
  legacyCbcKey?: LegacyKeyOwnership;
};

type CliDependencies = {
  args: string[];
  createClient: (url: string, key: string) => SupabaseClient;
  env: Environment;
  rotate: (
    client: SupabaseClient,
    options: {
      apply: boolean;
      legacyCbcKey?: LegacyKeyOwnership;
      report: (message: string) => void;
    }
  ) => Promise<RotationSummary>;
  stderr: (message: string) => void;
  stdout: (message: string) => void;
};

const USAGE = `Usage: npm run rotate-keys -- [--apply] [--legacy-cbc-key=current|previous]

Runs a read-only dry-run by default. --apply is disabled until RPC orchestration is implemented
in the next slice. Legacy CBC values require explicit key ownership whenever
ENCRYPTION_KEY_PREVIOUS is configured.`;

function parseArgs(args: string[]): CliOptions {
  const options: CliOptions = { apply: false, help: false };
  for (const arg of args) {
    if (arg === '--apply') options.apply = true;
    else if (arg === '--dry-run') options.apply = false;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--legacy-cbc-key=current')
      options.legacyCbcKey = 'current';
    else if (arg === '--legacy-cbc-key=previous') {
      options.legacyCbcKey = 'previous';
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
}

function validateEnvironment(env: Environment, options: CliOptions): string[] {
  const errors: string[] = [];
  if (!env.NEXT_PUBLIC_SUPABASE_URL)
    errors.push('NEXT_PUBLIC_SUPABASE_URL is required');
  if (!env.SUPABASE_SERVICE_ROLE_KEY)
    errors.push('SUPABASE_SERVICE_ROLE_KEY is required');
  if (!/^[a-f\d]{64}$/i.test(env.ENCRYPTION_KEY ?? '')) {
    errors.push(
      'ENCRYPTION_KEY must contain exactly 64 hexadecimal characters'
    );
  }
  if (
    env.ENCRYPTION_KEY_PREVIOUS &&
    !/^[a-f\d]{64}$/i.test(env.ENCRYPTION_KEY_PREVIOUS)
  ) {
    errors.push(
      'ENCRYPTION_KEY_PREVIOUS must contain exactly 64 hexadecimal characters'
    );
  }
  if (options.legacyCbcKey === 'previous' && !env.ENCRYPTION_KEY_PREVIOUS) {
    errors.push(
      'ENCRYPTION_KEY_PREVIOUS is required with --legacy-cbc-key=previous'
    );
  }
  return errors;
}

export async function runKeyRotationCli(
  dependencies: CliDependencies
): Promise<number> {
  let options: CliOptions;
  try {
    options = parseArgs(dependencies.args);
  } catch (error) {
    dependencies.stderr(error instanceof Error ? error.message : String(error));
    return 2;
  }

  if (options.help) {
    dependencies.stdout(USAGE);
    return 0;
  }

  if (options.apply) {
    dependencies.stderr(
      'RPC orchestration not enabled in this slice; --apply is disabled.'
    );
    return 1;
  }

  const environmentErrors = validateEnvironment(dependencies.env, options);
  if (environmentErrors.length > 0) {
    dependencies.stderr(environmentErrors.join('\n'));
    return 2;
  }

  try {
    const client = dependencies.createClient(
      dependencies.env.NEXT_PUBLIC_SUPABASE_URL!,
      dependencies.env.SUPABASE_SERVICE_ROLE_KEY!
    );
    const summary = await dependencies.rotate(client, {
      apply: options.apply,
      legacyCbcKey: options.legacyCbcKey,
      report: dependencies.stdout,
    });
    const detail = `${summary.planned} planned, ${summary.rotated} rotated, ${summary.skipped} skipped.`;
    if (summary.skipped > 0) {
      dependencies.stderr(`Key rotation incomplete: ${detail}`);
      return 1;
    }
    dependencies.stdout(
      options.apply
        ? `Key rotation complete: ${detail}`
        : `Dry run complete: ${detail}`
    );
    return 0;
  } catch (error) {
    dependencies.stderr(error instanceof Error ? error.message : String(error));
    return 1;
  }
}
