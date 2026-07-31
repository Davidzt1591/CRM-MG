import { describe, it, expect, vi, beforeEach } from "vitest";
import { POST } from "./route";

// Scenario C regression suite: transferring a conversation must create
// real notification rows for the target department's agents. The bug
// had three layers:
//   1. notifications.account_id is NOT NULL, but the insert sent null.
//   2. notifications.user_id references auth.users(id), but the route
//      sent profile_departments.profile_id (a profiles.id) instead of
//      the member's auth.users id.
//   3. 027's notifications table had no INSERT policy (only the
//      assignment trigger writes), so client inserts were RLS-denied.
// The migration 044 adds the INSERT policy; these tests pin the route
// to resolve account_id and the correct user_id.

const { createClient } = vi.hoisted(() => ({ createClient: vi.fn() }));

vi.mock("@/lib/supabase/server", () => ({
  createClient: () => createClient(),
}));

vi.mock("@/lib/auth/account", () => ({
  getCurrentAccount: vi.fn(),
  toErrorResponse: (err: unknown) => {
    if (err instanceof Error && err.message === "Unauthorized") {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
      });
    }
    return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403 });
  },
  UnauthorizedError: class extends Error {
    status = 401;
    constructor() {
      super("Unauthorized");
    }
  },
  ForbiddenError: class extends Error {
    status = 403;
    constructor(m: string) {
      super(m);
    }
  },
}));

vi.mock("@/lib/rate-limit", () => ({
  checkRateLimit: vi.fn(() => ({ success: true, remaining: 29, reset: 0, limit: 30 })),
  rateLimitResponse: vi.fn(),
  RATE_LIMITS: { adminAction: { limit: 30, windowMs: 60000 } },
}));

vi.mock("@/lib/departments", () => ({
  getDepartment: vi.fn(),
}));

vi.mock("@/lib/audit", () => ({
  recordAuditEvent: vi.fn(),
}));

import { getCurrentAccount } from "@/lib/auth/account";
import { getDepartment } from "@/lib/departments";

const mockCtx = {
  userId: "user-1",
  accountId: "acct-1",
  role: "admin" as const,
  account: { id: "acct-1", name: "Test Account" },
};

type StubConfig = { data?: unknown; error?: unknown };

/** Minimal fake supabase client that records the query chain. */
function makeSupabase(config: Record<string, Record<string, StubConfig>>) {
  const calls: Array<{ table: string; op: string; args: unknown[] }> = [];
  const resolve = (table: string, op: string) => {
    const entry = config[table]?.[op] ?? { data: null, error: null };
    return Promise.resolve(entry as { data: unknown; error: unknown });
  };
  const createChain = (table: string) => {
    const chain = {
      select(columns: string) {
        calls.push({ table, op: "select", args: [columns] });
        const selectChain = {
          eq(key: string, value: unknown) {
            calls.push({ table, op: "eq", args: [key, value] });
            const eqChain = {
              maybeSingle: () => resolve(table, "select"),
              // allow `await from().select().eq()` for list queries
              then: (onFulfilled: (v: unknown) => unknown) =>
                resolve(table, "select").then(onFulfilled),
            };
            return eqChain;
          },
        };
        return selectChain;
      },
      update(payload: unknown) {
        calls.push({ table, op: "update", args: [payload] });
        const updateChain = {
          eq: () => resolve(table, "update"),
        };
        return updateChain;
      },
      insert(payload: unknown) {
        calls.push({ table, op: "insert", args: [payload] });
        return resolve(table, "insert");
      },
    };
    return chain;
  };
  return { from: (table: string) => createChain(table), calls };
}

function makeRequest() {
  return new Request("http://localhost/api/conversations/conv-1/transfer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      departmentId: "22222222-2222-4222-8222-222222222222",
      note: "please handle",
    }),
  });
}

describe("POST /api/conversations/[id]/transfer — notifications (Scenario C)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    createClient.mockReset();
    vi.mocked(getCurrentAccount).mockResolvedValue(mockCtx as never);
    vi.mocked(getDepartment).mockResolvedValue({
      id: "dept-2",
      name: "Support",
    } as never);
  });

  it("resolves account_id on every notification row (never null)", async () => {
    const fake = makeSupabase({
      conversations: {
        select: {
          data: { id: "conv-1", account_id: "acct-1", department_id: "dept-1" },
          error: null,
        },
        update: { data: null, error: null },
      },
      profile_departments: {
        select: {
          data: [{ profile_id: "prof-1", profiles: { user_id: "user-2" } }],
          error: null,
        },
      },
      departments: { select: { data: { name: "Support" }, error: null } },
      notifications: { insert: { data: null, error: null } },
    });
    createClient.mockReturnValue(fake);

    const res = await POST(makeRequest(), {
      params: Promise.resolve({ id: "conv-1" }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });

    const insertCall = fake.calls.find((c) => c.table === "notifications" && c.op === "insert");
    expect(insertCall).toBeTruthy();
    const rows = insertCall!.args[0] as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(1);
    expect(rows[0].account_id).toBe("acct-1");
    expect(rows[0].account_id).not.toBeNull();
    expect(rows[0].type).toBe("conversation_assigned");
    expect(rows[0].conversation_id).toBe("conv-1");
    expect(rows[0].actor_user_id).toBe("user-1");
  });

  it("uses the member's auth.users id, not the profile id, as recipient", async () => {
    const fake = makeSupabase({
      conversations: {
        select: {
          data: { id: "conv-1", account_id: "acct-1", department_id: "dept-1" },
          error: null,
        },
        update: { data: null, error: null },
      },
      profile_departments: {
        select: {
          // profile_id differs from the auth.users id on purpose —
          // profiles.id and auth.users.id are distinct UUIDs.
          data: [
            { profile_id: "prof-1", profiles: { user_id: "user-2" } },
            { profile_id: "prof-2", profiles: { user_id: "user-3" } },
          ],
          error: null,
        },
      },
      departments: { select: { data: { name: "Support" }, error: null } },
      notifications: { insert: { data: null, error: null } },
    });
    createClient.mockReturnValue(fake);

    const res = await POST(makeRequest(), {
      params: Promise.resolve({ id: "conv-1" }),
    });
    expect(res.status).toBe(200);

    const insertCall = fake.calls.find((c) => c.table === "notifications" && c.op === "insert");
    const rows = insertCall!.args[0] as Array<Record<string, unknown>>;
    expect(rows.map((r) => r.user_id)).toEqual(["user-2", "user-3"]);
    // Regression guard: the member query must join profiles to fetch
    // the auth.users id instead of selecting profile_id alone.
    const memberSelect = fake.calls.find(
      (c) => c.table === "profile_departments" && c.op === "select",
    );
    expect(String(memberSelect!.args[0])).toContain("user_id");
    expect(String(memberSelect!.args[0])).toContain("profiles");
  });

  it("pins every notification row to the caller's account and actor", async () => {
    // Security guard for the 044 INSERT policy: the payload the route
    // sends must satisfy the policy's WITH CHECK — account_id is the
    // caller's account, recipients are same-account members, and
    // actor_user_id is always the caller (never spoofed).
    const fake = makeSupabase({
      conversations: {
        select: {
          data: { id: "conv-1", account_id: "acct-1", department_id: "dept-1" },
          error: null,
        },
        update: { data: null, error: null },
      },
      profile_departments: {
        select: {
          data: [
            { profile_id: "prof-1", profiles: { user_id: "user-2" } },
            { profile_id: "prof-2", profiles: { user_id: "user-3" } },
          ],
          error: null,
        },
      },
      departments: { select: { data: { name: "Support" }, error: null } },
      notifications: { insert: { data: null, error: null } },
    });
    createClient.mockReturnValue(fake);

    const res = await POST(makeRequest(), {
      params: Promise.resolve({ id: "conv-1" }),
    });
    expect(res.status).toBe(200);

    const insertCall = fake.calls.find((c) => c.table === "notifications" && c.op === "insert");
    const rows = insertCall!.args[0] as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      // 1) Row belongs to the caller's account.
      expect(row.account_id).toBe("acct-1");
      // 2) Recipient is a member of that account (from the department
      //    membership query), never a foreign user.
      expect(["user-2", "user-3"]).toContain(row.user_id);
      // 3) Actor pinned to the caller — satisfies actor_user_id = auth.uid().
      expect(row.actor_user_id).toBe("user-1");
    }
  });

  it("still succeeds when the target department has no members (no insert)", async () => {
    const fake = makeSupabase({
      conversations: {
        select: {
          data: { id: "conv-1", account_id: "acct-1", department_id: "dept-1" },
          error: null,
        },
        update: { data: null, error: null },
      },
      profile_departments: { select: { data: [], error: null } },
      notifications: { insert: { data: null, error: null } },
    });
    createClient.mockReturnValue(fake);

    const res = await POST(makeRequest(), {
      params: Promise.resolve({ id: "conv-1" }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(fake.calls.some((c) => c.table === "notifications" && c.op === "insert")).toBe(false);
  });

  it("returns 403 when the conversation does not belong to the caller's account", async () => {
    const fake = makeSupabase({
      conversations: {
        select: {
          data: { id: "conv-1", account_id: "OTHER-ACCOUNT", department_id: "dept-1" },
          error: null,
        },
      },
    });
    createClient.mockReturnValue(fake);

    const res = await POST(makeRequest(), {
      params: Promise.resolve({ id: "conv-1" }),
    });
    expect(res.status).toBe(403);
  });
});
