import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Static regression guard for the inbox conversation STATUS_COLORS map
// (src/components/inbox/conversation-list.tsx).
//
// STATUS_COLORS is typed Record<ConversationStatus, string>, so tsc
// already enforces exhaustiveness at compile time — the moment a new
// status is added to the union (types/index.ts) without a color here,
// `npx tsc --noEmit` fails. This test pins the CONTRACT the colors
// encode (one dot color per DB-legal status, migration 045 superset)
// so a reviewer sees intent in the diff, and so a future change that
// drops a color for the wrong reason is caught even if the union
// shrinks in lockstep. Hues: 'active' → emerald, 'waiting' → violet
// (design: must not clash with the existing palette — the app uses
// red/blue/orange/purple accents, emerald/violet are unused).

const SOURCE_PATH = join(
  process.cwd(),
  "src",
  "components",
  "inbox",
  "conversation-list.tsx",
);

describe("conversation-list STATUS_COLORS — 045 superset coverage", () => {
  const source = readFileSync(SOURCE_PATH, "utf8");

  it("declares a color for every DB-legal status (045 superset)", () => {
    for (const status of ["open", "active", "pending", "closed", "waiting"]) {
      expect(source).toMatch(new RegExp(`^\\s*${status}:`, "m"));
    }
  });

  it("keeps the existing semantic colors for open/pending/closed", () => {
    expect(source).toMatch(/\bopen:\s*"bg-primary"/);
    expect(source).toMatch(/\bpending:\s*"bg-amber-500"/);
    expect(source).toMatch(/\bclosed:\s*"bg-muted-foreground"/);
  });

  it("uses emerald for 'active' and violet for 'waiting' (new 043-era statuses)", () => {
    expect(source).toMatch(/\bactive:\s*"bg-emerald-500"/);
    expect(source).toMatch(/\bwaiting:\s*"bg-violet-500"/);
  });

  it("keeps inbox filters unchanged — only 'open','pending','closed' offered (back-compat)", () => {
    const filterSection = source.slice(source.indexOf("const FILTER_OPTIONS"));
    expect(filterSection).toMatch(/value: "open"/);
    expect(filterSection).toMatch(/value: "pending"/);
    expect(filterSection).toMatch(/value: "closed"/);
    expect(filterSection).not.toMatch(/value: "active"/);
    expect(filterSection).not.toMatch(/value: "waiting"/);
  });
});
