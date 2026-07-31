import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Static regression guard for migration 045 (followups integrity hotfix).
//
// The migration is SQL executed by Postgres at apply time — there is
// no database in the vitest environment — so this test pins the
// migration's SHAPE as text, exactly like
// src/supabase/migrations/044_fix_notifications_transfer_rls.test.ts.
// The LIVE verification (043 applied? 'open' row count? inserts
// broken?) is a pre-apply hard gate that must be run against the
// deployed Supabase before the migration is applied; this test only
// guarantees the file itself carries the agreed contract:
//
//   UP (additive only, no row migration):
//     1. conversations.status CHECK is a SUPERSET of 001 ∪ 043:
//        ('open','active','pending','closed','waiting')
//     2. DEFAULT stays 'open' (001) — 045 never touches it, so
//        omitted-status inserts resolve 'open' (MCRM-52/S1)
//     3. audit_logs.user_id becomes NULLABLE (system audits, MCRM-55)
//     4. salesforce_config gains webhook_secret (drift repair, D3)
//   DOWN (faithful reversal to 043, lossy by design — loudly):
//     1. remaps 'open' → 'pending' BEFORE restoring the 043 CHECK
//        (043 cannot hold 'open'; order matters)
//     2. restores 043's exact CHECK ('active','pending','closed','waiting')
//     3. DELETEs system audit rows (user_id IS NULL) then SET NOT NULL
//        (D4: system events have no auth.users FK target; dropping
//        non-attributable rows is preferred over fabricated attribution)

const MIGRATION_PATH = join(
  process.cwd(),
  "supabase",
  "migrations",
  "045_followups_integrity.sql",
);

describe("045_followups_integrity.sql — integrity contract", () => {
  const sql = readFileSync(MIGRATION_PATH, "utf8");
  const [, down] = sql.split(/^--\s*DOWN$/m);
  const up = sql.slice(0, sql.indexOf("-- DOWN") === -1 ? sql.length : sql.indexOf("-- DOWN"));

  it("splits into UP and DOWN sections", () => {
    expect(up).toBeTruthy();
    expect(down).toBeTruthy();
  });

  // ── UP ──────────────────────────────────────────────────────────

  it("UP: replaces conversations_status_check with the 001∪043 superset", () => {
    expect(up).toContain("DROP CONSTRAINT IF EXISTS conversations_status_check");
    expect(up).toMatch(
      /ADD\s+CONSTRAINT\s+conversations_status_check\s+CHECK\s*\(\s*status\s+IN\s*\(\s*'open'\s*,\s*'active'\s*,\s*'pending'\s*,\s*'closed'\s*,\s*'waiting'\s*\)\s*\)/i,
    );
  });

  it("UP: every 001∪043 status value is legal under the superset", () => {
    for (const value of ["open", "active", "pending", "closed", "waiting"]) {
      expect(up).toContain(`'${value}'`);
    }
  });

  it("UP: DEFAULT stays 'open' — 045 does not alter the conversations default", () => {
    expect(up).not.toMatch(
      /ALTER\s+TABLE\s+conversations\s+ALTER\s+COLUMN\s+status\s+SET\s+DEFAULT/i,
    );
    expect(up).not.toMatch(/SET\s+DEFAULT\s+'[^']*'\s*[;)]/i);
  });

  it("UP: no row migration — existing 'open'/'active' rows are untouched", () => {
    expect(up).not.toMatch(/UPDATE\s+conversations\s+SET\s+status/i);
    expect(up).not.toMatch(/DELETE\s+FROM/i);
  });

  it("UP: relaxes audit_logs.user_id to NULLABLE (system audits, MCRM-55)", () => {
    expect(up).toMatch(
      /ALTER\s+TABLE\s+audit_logs\s+ALTER\s+COLUMN\s+user_id\s+DROP\s+NOT\s+NULL/i,
    );
  });

  it("UP: repairs the missing salesforce_config.webhook_secret column (D3)", () => {
    expect(up).toMatch(
      /ALTER\s+TABLE\s+salesforce_config\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+webhook_secret\s+TEXT/i,
    );
  });

  // ── DOWN ────────────────────────────────────────────────────────

  it("DOWN: restores the exact 043 CHECK (no 'open')", () => {
    expect(down).toMatch(
      /ADD\s+CONSTRAINT\s+conversations_status_check\s+CHECK\s*\(\s*status\s+IN\s*\(\s*'active'\s*,\s*'pending'\s*,\s*'closed'\s*,\s*'waiting'\s*\)\s*\)/i,
    );
    const checkLine = down
      .split("\n")
      .find((l) => l.includes("ADD CONSTRAINT conversations_status_check"));
    expect(checkLine).toBeTruthy();
    expect(checkLine).not.toContain("'open'");
  });

  it("DOWN: remaps 'open' → 'pending' BEFORE restoring the 043 CHECK", () => {
    const remapIdx = down.indexOf("SET status = 'pending' WHERE status = 'open'");
    const addConstraintIdx = down.indexOf("ADD CONSTRAINT conversations_status_check");
    expect(remapIdx).toBeGreaterThan(-1);
    expect(addConstraintIdx).toBeGreaterThan(remapIdx);
  });

  it("DOWN: deletes system audit rows (user_id IS NULL) then re-locks NOT NULL", () => {
    expect(down).toMatch(/DELETE\s+FROM\s+audit_logs\s+WHERE\s+user_id\s+IS\s+NULL/i);
    const deleteIdx = down.search(/DELETE\s+FROM\s+audit_logs\s+WHERE\s+user_id\s+IS\s+NULL/i);
    const setNotNullIdx = down.search(
      /ALTER\s+TABLE\s+audit_logs\s+ALTER\s+COLUMN\s+user_id\s+SET\s+NOT\s+NULL/i,
    );
    expect(deleteIdx).toBeGreaterThan(-1);
    expect(setNotNullIdx).toBeGreaterThan(deleteIdx);
  });
});
