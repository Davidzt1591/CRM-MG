import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const npmCli = process.env.npm_execpath;
const servers: ReturnType<typeof createServer>[] = [];

afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve()))
          )
      )
  );
});

async function runActualCli(args: string[], corruptWebhook = false) {
  let requests = 0;
  const server = createServer((request, response) => {
    requests += 1;
    const corrupt =
      corruptWebhook && request.url?.includes('/rest/v1/webhook_endpoints');
    const body = corrupt ? '[{"id":"bad","secret":"not-encrypted"}]' : '[]';
    response.writeHead(200, {
      'content-range': corrupt ? '0-0/1' : '*/0',
      'content-type': 'application/json',
    });
    response.end(body);
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string')
    throw new Error('Missing test port');

  if (!npmCli) throw new Error('npm_execpath is required for the CLI test');
  try {
    const result = await execFileAsync(
      process.execPath,
      [npmCli, 'run', 'rotate-keys', '--', ...args],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          ENCRYPTION_KEY: 'a'.repeat(64),
          KEY_ROTATION_ENV_FILE: join(
            tmpdir(),
            `missing-key-rotation-${randomUUID()}`
          ),
          NEXT_PUBLIC_SUPABASE_URL: `http://127.0.0.1:${address.port}`,
          SUPABASE_SERVICE_ROLE_KEY: 'local-test-service-role',
        },
        timeout: 30_000,
      }
    );
    return { ...result, exitCode: 0, requests };
  } catch (error) {
    const failed = error as Error & {
      code: number;
      stderr: string;
      stdout: string;
    };
    return {
      exitCode: failed.code,
      requests,
      stderr: failed.stderr,
      stdout: failed.stdout,
    };
  }
}

describe('actual key rotation package entrypoint', () => {
  it('runs on injected environment without an env file and defaults to dry-run', async () => {
    const result = await runActualCli([]);

    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain(
      'Dry run complete: 0 planned, 0 rotated, 0 skipped.'
    );
    expect(result.requests).toBe(12);
  }, 30_000);

  it('accepts explicit --apply through the package script', async () => {
    const result = await runActualCli(['--apply']);

    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain(
      'Key rotation complete: 0 planned, 0 rotated, 0 skipped.'
    );
    expect(result.requests).toBe(12);
  }, 30_000);

  it('returns nonzero from the actual process when a row is skipped', async () => {
    const result = await runActualCli(['--apply'], true);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Key rotation incomplete');
    expect(result.stdout).not.toContain('Key rotation complete');
    expect(result.requests).toBe(12);
  }, 30_000);
});
