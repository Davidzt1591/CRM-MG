import { describe, it, expect, vi, beforeEach } from "vitest";
import { GET, PATCH, DELETE } from "./route";

vi.mock("@/lib/auth/account", () => ({
  requireRole: vi.fn(),
  getCurrentAccount: vi.fn(),
  toErrorResponse: (err: unknown) => {
    const status =
      err instanceof Object && "status" in (err as any)
        ? (err as any).status
        : 500;
    return new Response(JSON.stringify({ error: (err as any)?.message ?? "Error" }), {
      status,
    });
  },
}));

vi.mock("@/lib/rate-limit", () => ({
  checkRateLimit: vi.fn(() => ({ success: true, remaining: 29, reset: 0, limit: 30 })),
  rateLimitResponse: vi.fn(),
  RATE_LIMITS: { adminAction: { limit: 30, windowMs: 60000 } },
}));

vi.mock("@/lib/departments", () => ({
  getDepartment: vi.fn(),
  updateDepartment: vi.fn(),
  archiveDepartment: vi.fn(),
}));

vi.mock("@/lib/audit", () => ({
  recordAuditEvent: vi.fn(),
}));

import { getCurrentAccount, requireRole } from "@/lib/auth/account";
import { getDepartment, updateDepartment, archiveDepartment } from "@/lib/departments";

const mockCtx = {
  supabase: {} as any,
  userId: "user-1",
  accountId: "acct-1",
  role: "admin" as const,
  account: { id: "acct-1", name: "Test Account" },
};

const mockDept = {
  id: "dept-1",
  account_id: "acct-1",
  name: "Support",
  description: "Customer support",
  created_at: "2026-01-01T00:00:00Z",
  archived_at: null,
};

describe("GET /api/departments/[id]", () => {
  beforeEach(() => vi.clearAllMocks());

  it("returns department when found", async () => {
    vi.mocked(getCurrentAccount).mockResolvedValue(mockCtx);
    vi.mocked(getDepartment).mockResolvedValue(mockDept);

    const res = await GET(new Request("http://localhost/api/departments/dept-1"), {
      params: Promise.resolve({ id: "dept-1" }),
    } as any);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.department.name).toBe("Support");
  });

  it("returns 404 when department not found", async () => {
    vi.mocked(getCurrentAccount).mockResolvedValue(mockCtx);
    vi.mocked(getDepartment).mockResolvedValue(null);

    const res = await GET(new Request("http://localhost/api/departments/dept-404"), {
      params: Promise.resolve({ id: "dept-404" }),
    } as any);
    expect(res.status).toBe(404);
  });
});

describe("PATCH /api/departments/[id]", () => {
  beforeEach(() => vi.clearAllMocks());

  it("updates department name", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);
    vi.mocked(getDepartment).mockResolvedValue(mockDept);
    vi.mocked(updateDepartment).mockResolvedValue({
      ...mockDept,
      name: "Premium Support",
    });

    const req = new Request("http://localhost/api/departments/dept-1", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Premium Support" }),
    });
    const res = await PATCH(req, {
      params: Promise.resolve({ id: "dept-1" }),
    } as any);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.department.name).toBe("Premium Support");
  });

  it("returns 404 when department not found", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);
    vi.mocked(getDepartment).mockResolvedValue(null);

    const req = new Request("http://localhost/api/departments/dept-404", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "New Name" }),
    });
    const res = await PATCH(req, {
      params: Promise.resolve({ id: "dept-404" }),
    } as any);
    expect(res.status).toBe(404);
  });

  it("returns 400 for invalid body", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);
    vi.mocked(getDepartment).mockResolvedValue(mockDept);

    const req = new Request("http://localhost/api/departments/dept-1", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "" }),
    });
    const res = await PATCH(req, {
      params: Promise.resolve({ id: "dept-1" }),
    } as any);
    expect(res.status).toBe(400);
  });
});

describe("DELETE /api/departments/[id]", () => {
  beforeEach(() => vi.clearAllMocks());

  it("archives a department", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);
    vi.mocked(getDepartment).mockResolvedValue(mockDept);
    vi.mocked(archiveDepartment).mockResolvedValue(undefined);

    const res = await DELETE(new Request("http://localhost/api/departments/dept-1"), {
      params: Promise.resolve({ id: "dept-1" }),
    } as any);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
  });

  it("returns 404 when department not found", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);
    vi.mocked(getDepartment).mockResolvedValue(null);

    const res = await DELETE(new Request("http://localhost/api/departments/dept-404"), {
      params: Promise.resolve({ id: "dept-404" }),
    } as any);
    expect(res.status).toBe(404);
  });
});
