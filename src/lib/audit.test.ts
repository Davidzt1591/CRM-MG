import { describe, expect, it, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// The audit write path must use the service-role admin client (SEC-02:
// append-only via service-role; client RLS read-only). Both supabase
// client modules are mocked so we can PROVE the insert goes through the
// admin client and the anon SSR client is never touched — if the write
// path regressed to the cookie-based client, RLS would deny every insert
// and audit events would silently vanish.
// ---------------------------------------------------------------------------

const adminInsert = vi.fn();
vi.mock("@/lib/supabase/admin", () => ({
  createAdminClient: () => ({
    from: () => ({ insert: adminInsert }),
  }),
}));

const serverInsert = vi.fn();
vi.mock("@/lib/supabase/server", () => ({
  createClient: () => ({
    from: () => ({ insert: serverInsert }),
  }),
}));

const { recordAuditEvent } = await import("./audit");

describe("recordAuditEvent", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("writes via the service-role admin client, never the anon SSR client", async () => {
    adminInsert.mockResolvedValue({ error: null });

    await recordAuditEvent({
      accountId: "acct-1",
      userId: "user-1",
      action: "department.create",
      targetType: "department",
    });

    expect(adminInsert).toHaveBeenCalledTimes(1);
    expect(serverInsert).not.toHaveBeenCalled();
  });

  it("maps params to the audit_logs column shape", async () => {
    adminInsert.mockResolvedValue({ error: null });

    await recordAuditEvent({
      accountId: "acct-1",
      userId: "user-1",
      action: "department.create",
      targetType: "department",
      targetId: "dept-1",
      oldValues: { name: "Support" },
      newValues: { name: "Sales" },
      ipAddress: "10.0.0.1",
    });

    expect(adminInsert).toHaveBeenCalledWith({
      account_id: "acct-1",
      user_id: "user-1",
      action: "department.create",
      target_type: "department",
      target_id: "dept-1",
      old_values: { name: "Support" },
      new_values: { name: "Sales" },
      ip_address: "10.0.0.1",
    });
  });

  it("defaults optional columns to null", async () => {
    adminInsert.mockResolvedValue({ error: null });

    await recordAuditEvent({
      accountId: "acct-1",
      userId: "user-1",
      action: "provider.switch",
      targetType: "whatsapp_config",
    });

    expect(adminInsert).toHaveBeenCalledWith({
      account_id: "acct-1",
      user_id: "user-1",
      action: "provider.switch",
      target_type: "whatsapp_config",
      target_id: null,
      old_values: null,
      new_values: null,
      ip_address: null,
    });
  });

  it("maps the 'system' sentinel to user_id NULL (MCRM-55/D11)", async () => {
    // System-triggered events (Salesforce CDC webhook, escalation sync)
    // have no auth.users FK target. recordAuditEvent must map the
    // 'system' sentinel to NULL — with 045 relaxing the NOT NULL, the
    // insert succeeds; the raw sentinel would violate the FK (037).
    adminInsert.mockResolvedValue({ error: null });

    await recordAuditEvent({
      accountId: "acct-1",
      userId: "system",
      action: "salesforce.cdc_received",
      targetType: "salesforce_case_mapping",
      targetId: "map-1",
    });

    expect(adminInsert).toHaveBeenCalledWith(
      expect.objectContaining({ user_id: null }),
    );
  });

  it("maps an omitted userId to user_id NULL", async () => {
    adminInsert.mockResolvedValue({ error: null });

    await recordAuditEvent({
      accountId: "acct-1",
      action: "salesforce.escalated",
      targetType: "conversation",
      targetId: "conv-1",
    });

    expect(adminInsert).toHaveBeenCalledWith(
      expect.objectContaining({ user_id: null }),
    );
  });

  it("does not throw when the insert fails — it logs and swallows", async () => {
    adminInsert.mockResolvedValue({ error: { message: "permission denied" } });
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(
      recordAuditEvent({
        accountId: "acct-1",
        userId: "user-1",
        action: "x",
        targetType: "y",
      }),
    ).resolves.toBeUndefined();

    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it("does not throw when the insert rejects (network error)", async () => {
    adminInsert.mockRejectedValue(new Error("network down"));

    await expect(
      recordAuditEvent({
        accountId: "acct-1",
        userId: "user-1",
        action: "x",
        targetType: "y",
      }),
    ).resolves.toBeUndefined();
  });
});
