import { createClient } from '@supabase/supabase-js';
import {
  rotateEncryptedColumns,
  shouldApplyRotation,
} from '../src/lib/ops/key-rotation.ts';

const apply = shouldApplyRotation(process.argv.slice(2));
const client = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

try {
  console.log(
    apply
      ? 'Applying encryption key rotation.'
      : 'Dry run only; pass --apply to write changes.'
  );
  const summary = await rotateEncryptedColumns(client, { apply });
  console.log(
    `Key rotation complete: ${summary.planned} planned, ${summary.rotated} rotated, ${summary.skipped} skipped.`
  );
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
