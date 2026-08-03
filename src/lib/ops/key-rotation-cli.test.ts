import type { SupabaseClient } from '@supabase/supabase-js';
import { describe, expect, it, vi } from 'vitest';
import type { RotationSummary } from './key-rotation';

const VALID_ENV = {
  NEXT_PUBLIC_SUPABASE_URL: 'https://example.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: 'service-role',
  ENCRYPTION_KEY: 'a'.repeat(64),
};

async function run(
  args: string[],
  summary: RotationSummary = { planned: 1, rotated: 0, skipped: 0 },
  env: Record<string, string | undefined> = VALID_ENV
) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const rotate = vi.fn(async () => summary);
  const createClient = vi.fn(() => ({}) as SupabaseClient);
  const { runKeyRotationCli } = await import('./key-rotation-cli');
  const exitCode = await runKeyRotationCli({
    args,
    env,
    createClient,
    rotate,
    stdout: (message) => stdout.push(message),
    stderr: (message) => stderr.push(message),
  });
  return { createClient, exitCode, rotate, stderr, stdout };
}

describe('key rotation CLI contract', () => {
  it('prints help without requiring an environment or database client', async () => {
    const result = await run(['--help'], undefined, {});

    expect(result.exitCode).toBe(0);
    expect(result.stdout.join('\n')).toContain('Usage:');
    expect(result.createClient).not.toHaveBeenCalled();
  });

  it('validates required environment variables before creating a client', async () => {
    const result = await run([], undefined, {});

    expect(result.exitCode).toBe(2);
    expect(result.stderr.join('\n')).toContain('ENCRYPTION_KEY');
    expect(result.createClient).not.toHaveBeenCalled();
  });

  it('defaults to dry-run and reports a dry-run summary', async () => {
    const result = await run([]);

    expect(result.exitCode).toBe(0);
    expect(result.rotate).toHaveBeenCalledWith(expect.anything(), {
      apply: false,
      legacyCbcKey: undefined,
      report: expect.any(Function),
    });
    expect(result.stdout.at(-1)).toBe(
      'Dry run complete: 1 planned, 0 rotated, 0 skipped.'
    );
  });

  it('applies only with --apply and reports successful output', async () => {
    const result = await run(['--apply'], {
      planned: 2,
      rotated: 2,
      skipped: 0,
    });

    expect(result.exitCode).toBe(0);
    expect(result.rotate).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ apply: true })
    );
    expect(result.stdout.at(-1)).toContain('Key rotation complete');
  });

  it('returns nonzero and never claims success when apply leaves skipped rows', async () => {
    const result = await run(['--apply'], {
      planned: 2,
      rotated: 1,
      skipped: 1,
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr.at(-1)).toContain('incomplete');
    expect(result.stdout.join('\n')).not.toContain('Key rotation complete');
  });

  it('passes explicit previous-key ownership for legacy CBC rows', async () => {
    const result = await run(
      ['--apply', '--legacy-cbc-key=previous'],
      undefined,
      { ...VALID_ENV, ENCRYPTION_KEY_PREVIOUS: 'b'.repeat(64) }
    );

    expect(result.rotate).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ legacyCbcKey: 'previous' })
    );
  });

  it('returns nonzero on traversal failures', async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const { runKeyRotationCli } = await import('./key-rotation-cli');
    const exitCode = await runKeyRotationCli({
      args: [],
      env: VALID_ENV,
      createClient: () => ({}) as SupabaseClient,
      rotate: async () => {
        throw new Error('incomplete traversal');
      },
      stdout: (message) => stdout.push(message),
      stderr: (message) => stderr.push(message),
    });

    expect(exitCode).toBe(1);
    expect(stderr).toContain('incomplete traversal');
    expect(stdout.join('\n')).not.toContain('complete');
  });
});
