import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Static regression guard for migration 044's notifications INSERT
// policy (cross-account spoofing, HIGH finding from the security
// review of the resolve-blockers batch).
//
// The policy is SQL executed by Postgres at migration time — there is
// no database in the vitest environment — so this test pins the
// policy's SECURITY SHAPE as text: it must keep all three
// WITH CHECK clauses that together kill the spoofing vector:
//   1. account_id = caller's account        (row stays in the caller's account)
//   2. user_id IN (same-account profiles)   (recipient is an account member, never a foreign user)
//   3. actor_user_id = auth.uid()           (the actor is pinned to the caller)
//
// If the migration is ever edited, this test fails loudly until the
// security properties are re-confirmed.

const MIGRATION_PATH = join(
  process.cwd(),
  "supabase",
  "migrations",
  "044_fix_notifications_transfer_rls.sql",
);

describe("044_fix_notifications_transfer_rls.sql — INSERT policy shape", () => {
  const sql = readFileSync(MIGRATION_PATH, "utf8");

  it("defines a FOR INSERT policy on notifications", () => {
    expect(sql).toMatch(/CREATE\s+POLICY\s+notifications_insert\s+ON\s+notifications\s+FOR\s+INSERT/);
  });

  it("scopes the row to the caller's own account", () => {
    expect(sql).toContain(
      "account_id = (SELECT p.account_id FROM profiles p WHERE p.user_id = auth.uid())",
    );
  });

  it("restricts recipients to members of that same account (no cross-account delivery)", () => {
    // user_id IN (...) over profiles — the recipient must have a
    // profile in the SAME account as the row. profiles.user_id is
    // UNIQUE, so membership is exact, and comparing against the
    // qualified row column (notifications.account_id) is what makes
    // the correlation safe — an unqualified `account_id = account_id`
    // would self-reference and be vacuously true.
    expect(sql).toMatch(/user_id\s+IN\s*\(/);
    expect(sql).toContain("m.account_id = notifications.account_id");
  });

  it("pins the actor to the authenticated caller (no spoofed actor_user_id)", () => {
    expect(sql).toContain("actor_user_id = auth.uid()");
  });

  it("does not contain the vacuous self-comparison trap", () => {
    expect(sql).not.toMatch(/WHERE\s+account_id\s*=\s*account_id(?:\s|\))/);
  });
});
