import { createClient } from '@supabase/supabase-js';
import { config } from 'dotenv';

config({
  path: process.env.KEY_ROTATION_ENV_FILE ?? '.env.local',
  override: false,
  quiet: true,
});

async function main(): Promise<void> {
  const [{ runKeyRotationCli }, { rotateEncryptedColumns }] = await Promise.all(
    [
      import('../src/lib/ops/key-rotation-cli'),
      import('../src/lib/ops/key-rotation'),
    ]
  );

  process.exitCode = await runKeyRotationCli({
    args: process.argv.slice(2),
    createClient,
    env: process.env,
    rotate: rotateEncryptedColumns,
    stderr: console.error,
    stdout: console.log,
  });
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
