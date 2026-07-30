import { describe, it, expect } from "vitest";

// Test the pure normalization logic directly (no mocks needed)
// by testing the shape that Supabase aggregates return.
interface RawDepartment {
  id: string;
  account_id: string;
  name: string;
  description: string | null;
  created_at: string;
  archived_at: string | null;
  member_count?: { count: number } | number | null;
}

function normalizeDepartment(raw: RawDepartment) {
  const { member_count, ...rest } = raw;
  let count: number | undefined;

  if (typeof member_count === "number") {
    count = member_count;
  } else if (member_count && typeof member_count === "object") {
    count = ("count" in member_count
      ? (member_count as { count: number }).count
      : (member_count as { length?: number }).length) ?? undefined;
  }

  return { ...rest, member_count: count };
}

describe("normalizeDepartment", () => {
  it("extracts count from Supabase aggregate format", () => {
    const raw: RawDepartment = {
      id: "dept-1",
      account_id: "acct-1",
      name: "Support",
      description: null,
      created_at: "2026-01-01T00:00:00Z",
      archived_at: null,
      member_count: { count: 5 },
    };

    const result = normalizeDepartment(raw);
    expect(result.member_count).toBe(5);
    expect(result.name).toBe("Support");
  });

  it("passes through numeric count directly", () => {
    const raw: RawDepartment = {
      id: "dept-2",
      account_id: "acct-1",
      name: "Sales",
      description: "Handles inbound sales",
      created_at: "2026-01-01T00:00:00Z",
      archived_at: null,
      member_count: 3,
    };

    const result = normalizeDepartment(raw);
    expect(result.member_count).toBe(3);
  });

  it("handles null/undefined member_count gracefully", () => {
    const raw: RawDepartment = {
      id: "dept-3",
      account_id: "acct-1",
      name: "Billing",
      description: null,
      created_at: "2026-01-01T00:00:00Z",
      archived_at: null,
      member_count: null,
    };

    const result = normalizeDepartment(raw);
    expect(result.member_count).toBeUndefined();
  });

  it("handles missing member_count", () => {
    const raw = {
      id: "dept-4",
      account_id: "acct-1",
      name: "Operations",
      description: null,
      created_at: "2026-01-01T00:00:00Z",
      archived_at: null,
    } as RawDepartment;

    const result = normalizeDepartment(raw);
    expect(result.member_count).toBeUndefined();
  });

  it("preserves archived_at when set", () => {
    const raw: RawDepartment = {
      id: "dept-5",
      account_id: "acct-1",
      name: "Old Dept",
      description: null,
      created_at: "2026-01-01T00:00:00Z",
      archived_at: "2026-06-01T00:00:00Z",
      member_count: { count: 0 },
    };

    const result = normalizeDepartment(raw);
    expect(result.archived_at).toBe("2026-06-01T00:00:00Z");
    expect(result.member_count).toBe(0);
  });
});
