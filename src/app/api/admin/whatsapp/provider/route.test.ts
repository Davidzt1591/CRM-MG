import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// MCRM-58: /api/admin/whatsapp/provider GET+POST MUST enforce requireRole("admin").
//
// The provider route previously authenticated with getUser() + a manual
// resolveAccountId() lookup and had NO role check — a member could therefore
// GET their masked config (acceptable) but the route structure invited a
// future role bypass, and a missing-profile / RLS edge could surface as a 500
// rather than a clean 403. This test enforces the audit-logs pattern:
// requireRole("admin") gates both verbs; non-admins get 403 with no DB access
// (no data leak, no RLS 500); admins get masked config / persisted + audited
// writes sourced from the requireRole context (userId, accountId).
// ---------------------------------------------------------------------------

// Mock the service dependencies so the route is fully hermetic.
vi.mock("@/lib/whatsapp/encryption", () => ({
  encrypt: vi.fn((s: string) => `enc:${s}`),
  decrypt: vi.fn((s: string) => `dec:${s}`),
}));
vi.mock("@/lib/audit", () => ({
  recordAuditEvent: vi.fn().mockResolvedValue(undefined),
}));
// auth/account: keep the REAL toErrorResponse + typed error classes so the
// 401/403 status mapping is exercised end-to-end; replace only requireRole
// (the gate under test).
vi.mock("@/lib/auth/account", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/auth/account")>()),
  requireRole: vi.fn(),
}));

// Imported AFTER the mocks are registered.
import { GET, POST } from "./route";
import { requireRole, ForbiddenError } from "@/lib/auth/account";
import { encrypt } from "@/lib/whatsapp/encryption";
import { recordAuditEvent } from "@/lib/audit";

// --- Fake Supabase client -------------------------------------------------
// Records the from/select/eq/maybeSingle/insert/update chain so tests can
// assert *no* DB access on the 403 path (no leak, no RLS 500). Only
// whatsapp_config is reachable — the route no longer touches profiles
// directly (accountId/userId come from the requireRole context).
function makeSupabase({
  config = null,
  selectError = null,
  writeError = null,
}: {
  config?: unknown | null;
  selectError?: unknown;
  writeError?: unknown;
} = {}) {
  const calls: Array<{ op: string; table?: string; args: unknown[] }> = [];

  function makeChain(table: string) {
    return {
      select(columns: string) {
        calls.push({ op: "select", table, args: [columns] });
        return {
          eq(col: string, val: unknown) {
            calls.push({ op: "eq", table, args: [col, val] });
            return {
              maybeSingle: async () => ({ data: config, error: selectError }),
            };
          },
        };
      },
      insert(obj: unknown) {
        calls.push({ op: "insert", table, args: [obj] });
        return Promise.resolve({ data: null, error: writeError });
      },
      update(obj: unknown) {
        calls.push({ op: "update", table, args: [obj] });
        return {
          eq(col: string, val: unknown) {
            calls.push({ op: "eq", table, args: [col, val] });
            return Promise.resolve({ data: null, error: writeError });
          },
        };
      },
    };
  }

  const client = {
    from(table: string) {
      calls.push({ op: "from", args: [table] });
      return makeChain(table);
    },
  };

  return { client: client as any, calls };
}

// Account context returned by the (mocked) requireRole("admin") for admins.
// userId is a DISTINCT sentinel from the session user ("session-user") so a
// regression that reads the session user instead of ctx.userId is caught.
const mockCtx = {
  supabase: null as any,
  userId: "attribution-user",
  accountId: "acct-1",
  role: "admin" as const,
  account: { id: "acct-1", name: "Test Account" },
};

const CONFIG_ROW = {
  provider: "meta",
  provider_config: { apiKey: "real-key", secret: "real-secret" },
  phone_number_id: "PNID",
  waba_id: "WABA",
};

beforeEach(() => {
  vi.clearAllMocks();
  mockCtx.supabase = makeSupabase().client;
});

describe("GET /api/admin/whatsapp/provider — role gate (MCRM-58)", () => {
  it("returns 403 for a member with NO database access (no leak, no RLS 500)", async () => {
    const { client, calls } = makeSupabase({ config: CONFIG_ROW });
    mockCtx.supabase = client;
    vi.mocked(requireRole).mockRejectedValue(
      new ForbiddenError("Insufficient role"),
    );

    const res = await GET();

    expect(res.status).toBe(403);
    // The route must bail out at requireRole BEFORE touching whatsapp_config
    // — no row read means there is nothing for RBAC/RLS to leak or 500 on.
    expect(calls.map((c) => c.op)).not.toContain("select");
    expect(calls.filter((c) => c.table === "whatsapp_config")).toHaveLength(0);
  });

  it("returns 200 with masked secrets for an admin", async () => {
    const { client } = makeSupabase({ config: CONFIG_ROW });
    mockCtx.supabase = client;
    vi.mocked(requireRole).mockResolvedValue(mockCtx as never);

    const res = await GET();

    expect(res.status).toBe(200);
    const body = await res.json();
    // Sensitive values are masked, never echoed.
    expect(body.api_key).toBe("••••••••••••••••");
    expect(body.webhook_secret).toBe("••••••••••••••••");
    expect(body.api_key).not.toBe("real-key");
    expect(body.webhook_secret).not.toBe("real-secret");
    expect(body.provider).toBe("meta");
    expect(body.phone_number_id).toBe("PNID");
    expect(body.waba_id).toBe("WABA");
  });
});

describe("POST /api/admin/whatsapp/provider — role gate (MCRM-58)", () => {
  it("returns 403 for a member POST with NO database access", async () => {
    const { client, calls } = makeSupabase({ config: CONFIG_ROW });
    mockCtx.supabase = client;
    vi.mocked(requireRole).mockRejectedValue(
      new ForbiddenError("Insufficient role"),
    );

    const req = new Request("http://localhost/api/admin/whatsapp/provider", {
      method: "POST",
      body: JSON.stringify({ provider: "openwa", api_key: "k", webhook_secret: "s" }),
    });

    const res = await POST(req);

    expect(res.status).toBe(403);
    // No config read, no encrypt, no insert/update, no audit — the gate holds
    // before any privileged work happens.
    expect(calls.filter((c) => c.table === "whatsapp_config")).toHaveLength(0);
    expect(encrypt).not.toHaveBeenCalled();
    expect(recordAuditEvent).not.toHaveBeenCalled();
  });

  it("admin POST persists an openwa provider switch: encrypts, updates, audits with ctx.userId", async () => {
    const { client, calls } = makeSupabase({ config: { provider: "meta" } });
    mockCtx.supabase = client;
    vi.mocked(requireRole).mockResolvedValue(mockCtx as never);

    const req = new Request("http://localhost/api/admin/whatsapp/provider", {
      method: "POST",
      body: JSON.stringify({
        provider: "openwa",
        api_url: "https://wa.example.com/",
        api_key: "secret-api-key",
        webhook_secret: "secret-webhook",
      }),
    });

    const res = await POST(req);

    expect(res.status).toBe(200);
    // Secrets encrypted (not stored raw).
    expect(encrypt).toHaveBeenCalledWith("secret-api-key");
    expect(encrypt).toHaveBeenCalledWith("secret-webhook");
    // Existing row ⇒ UPDATE path, scoped to the account.
    const updateCalls = calls.filter((c) => c.op === "update");
    expect(updateCalls).toHaveLength(1);
    const eqCalls = calls.filter((c) => c.op === "eq");
    expect(eqCalls.some((c) => c.args[0] === "account_id")).toBe(true);
    // Provider switch audited, attributed to the requireRole context user
    // (NOT the raw session user id).
    expect(recordAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "attribution-user",
        accountId: "acct-1",
        action: "provider.switched",
        targetType: "whatsapp_config",
        oldValues: { provider: "meta" },
        newValues: { provider: "openwa" },
      }),
    );
  });

  it("admin POST with no existing config INSERTs (user_id from ctx, no switch audit)", async () => {
    const { client, calls } = makeSupabase({ config: null });
    mockCtx.supabase = client;
    vi.mocked(requireRole).mockResolvedValue(mockCtx as never);

    const req = new Request("http://localhost/api/admin/whatsapp/provider", {
      method: "POST",
      body: JSON.stringify({
        provider: "meta",
        phone_number_id: "PNID-2",
        waba_id: "WABA-2",
      }),
    });

    const res = await POST(req);

    expect(res.status).toBe(200);
    const insertCalls = calls.filter((c) => c.op === "insert");
    expect(insertCalls).toHaveLength(1);
    const inserted = insertCalls[0].args[0] as Record<string, unknown>;
    // account_id + user_id come from the requireRole context, not a separate
    // getUser()/resolveAccountId() lookup.
    expect(inserted.account_id).toBe("acct-1");
    expect(inserted.user_id).toBe("attribution-user");
    expect(inserted.provider).toBe("meta");
    // No previous provider ⇒ no switch ⇒ no audit event.
    expect(recordAuditEvent).not.toHaveBeenCalled();
  });
});
