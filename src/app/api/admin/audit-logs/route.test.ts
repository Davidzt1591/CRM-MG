import { describe, it, expect, vi, beforeEach } from "vitest";
import { GET } from "./route";

// MCRM-24: the audit-logs API powers the admin audit trail viewer.
// Reads are scoped to the caller's account and require owner/admin
// (requireRole("admin")); the 037 RLS policy already permits exactly
// that read set, and the route filters by account_id explicitly to
// keep the discipline visible.

vi.mock("@/lib/auth/account", () => ({
  requireRole: vi.fn(),
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

import { requireRole } from "@/lib/auth/account";

/** Fake supabase client that records the from/select/eq/order/limit chain. */
function makeSupabase({ logs, error }: { logs?: unknown[]; error?: unknown }) {
  const calls: Array<{ op: string; args: unknown[] }> = [];
  const chain = {
    select(columns: string) {
      calls.push({ op: "select", args: [columns] });
      const selectChain = {
        eq(key: string, value: unknown) {
          calls.push({ op: "eq", args: [key, value] });
          const eqChain = {
            order(column: string, opts?: unknown) {
              calls.push({ op: "order", args: [column, opts] });
              const orderChain = {
                limit: (n: number) => {
                  calls.push({ op: "limit", args: [n] });
                  return Promise.resolve({ data: logs ?? [], error: error ?? null });
                },
                // if the route awaits before limit (should not happen)
                then: (onFulfilled: (v: unknown) => unknown) =>
                  Promise.resolve({ data: logs ?? [], error: error ?? null }).then(
                    onFulfilled,
                  ),
              };
              return orderChain;
            },
            then: (onFulfilled: (v: unknown) => unknown) =>
              Promise.resolve({ data: logs ?? [], error: error ?? null }).then(
                onFulfilled,
              ),
          };
          return eqChain;
        },
      };
      return selectChain;
    },
  };
  return { from: () => chain, calls };
}

const mockCtx = {
  supabase: {} as any,
  userId: "user-1",
  accountId: "acct-1",
  role: "admin" as const,
  account: { id: "acct-1", name: "Test Account" },
};

describe("GET /api/admin/audit-logs", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 401 when not authenticated", async () => {
    vi.mocked(requireRole).mockRejectedValue(
      Object.assign(new Error("Unauthorized"), { status: 401 }),
    );

    const res = await GET(new Request("http://localhost/api/admin/audit-logs"));
    expect(res.status).toBe(401);
  });

  it("returns 403 when the caller is not owner/admin", async () => {
    const { ForbiddenError } = await import("@/lib/auth/account");
    vi.mocked(requireRole).mockRejectedValue(
      new ForbiddenError("Insufficient role"),
    );

    const res = await GET(new Request("http://localhost/api/admin/audit-logs"));
    expect(res.status).toBe(403);
  });

  it("returns the account's audit logs scoped by account_id", async () => {
    const logs = [
      {
        id: "log-1",
        user_id: "user-2",
        action: "department.create",
        target_type: "department",
        target_id: "dept-9",
        old_values: null,
        new_values: { name: "Support" },
        ip_address: "127.0.0.1",
        created_at: "2026-01-01T00:00:00Z",
      },
    ];
    const fake = makeSupabase({ logs });
    mockCtx.supabase = fake;
    vi.mocked(requireRole).mockResolvedValue(mockCtx as never);

    const res = await GET(new Request("http://localhost/api/admin/audit-logs"));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.logs).toEqual(logs);

    const ops = fake.calls.map((c) => c.op);
    expect(ops).toContain("select");
    const eq = fake.calls.find((c) => c.op === "eq");
    expect(eq!.args).toEqual(["account_id", "acct-1"]);
    const order = fake.calls.find((c) => c.op === "order");
    expect(order!.args[0]).toBe("created_at");
    expect(order!.args[1]).toMatchObject({ ascending: false });
    const limit = fake.calls.find((c) => c.op === "limit");
    expect(limit!.args).toEqual([100]);
  });

  it("honours a valid ?limit= parameter", async () => {
    const fake = makeSupabase({ logs: [] });
    mockCtx.supabase = fake;
    vi.mocked(requireRole).mockResolvedValue(mockCtx as never);

    const res = await GET(
      new Request("http://localhost/api/admin/audit-logs?limit=25"),
    );
    expect(res.status).toBe(200);
    const limit = fake.calls.find((c) => c.op === "limit");
    expect(limit!.args).toEqual([25]);
  });

  it("rejects out-of-range limits with 400", async () => {
    const fake = makeSupabase({ logs: [] });
    mockCtx.supabase = fake;
    vi.mocked(requireRole).mockResolvedValue(mockCtx as never);

    const res = await GET(
      new Request("http://localhost/api/admin/audit-logs?limit=9999"),
    );
    expect(res.status).toBe(400);
  });

  it("returns 500 with a helpful error when the query fails", async () => {
    const fake = makeSupabase({ logs: [], error: { message: "boom" } });
    mockCtx.supabase = fake;
    vi.mocked(requireRole).mockResolvedValue(mockCtx as never);

    const res = await GET(new Request("http://localhost/api/admin/audit-logs"));
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toMatch(/audit/i);
  });
});
