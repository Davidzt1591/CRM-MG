import { describe, it, expect, vi, beforeEach } from "vitest";
import { GET, POST } from "./route";

// Mock the auth module — routes call requireRole / getCurrentAccount
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

vi.mock("@/lib/rate-limit", () => ({
  checkRateLimit: vi.fn(() => ({ success: true, remaining: 29, reset: 0, limit: 30 })),
  rateLimitResponse: vi.fn(),
  RATE_LIMITS: { adminAction: { limit: 30, windowMs: 60000 } },
}));

vi.mock("@/lib/departments", () => ({
  listDepartments: vi.fn(),
  createDepartment: vi.fn(),
}));

vi.mock("@/lib/audit", () => ({
  recordAuditEvent: vi.fn(),
}));

import { requireRole } from "@/lib/auth/account";
import { listDepartments, createDepartment } from "@/lib/departments";

const mockCtx = {
  supabase: {} as any,
  userId: "user-1",
  accountId: "acct-1",
  role: "admin" as const,
  account: { id: "acct-1", name: "Test Account" },
};

describe("GET /api/departments", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 401 when not authenticated", async () => {
    vi.mocked(requireRole).mockRejectedValue(new Error("Unauthorized"));

    const res = await GET();
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe("Unauthorized");
  });

  it("returns 403 when role is too low", async () => {
    vi.mocked(requireRole).mockRejectedValue(
      Object.assign(new Error("This action requires the 'agent' role or higher"), {
        status: 403,
      }),
    );

    // We need to handle the ForbiddenError properly
    vi.mocked(requireRole).mockImplementation(async () => {
      const { ForbiddenError } = await import("@/lib/auth/account");
      throw new ForbiddenError("This action requires the 'agent' role or higher");
    });

    const res = await GET();
    expect(res.status).toBe(403);
  });

  it("returns departments list for authenticated user", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);
    vi.mocked(listDepartments).mockResolvedValue([
      {
        id: "dept-1",
        account_id: "acct-1",
        name: "Support",
        description: null,
        created_at: "2026-01-01T00:00:00Z",
        archived_at: null,
        member_count: 3,
      },
    ]);

    const res = await GET();
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.departments).toHaveLength(1);
    expect(body.departments[0].name).toBe("Support");
    expect(body.departments[0].member_count).toBe(3);
  });

  it("returns empty array when no departments exist", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);
    vi.mocked(listDepartments).mockResolvedValue([]);

    const res = await GET();
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.departments).toEqual([]);
  });
});

describe("POST /api/departments", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("creates and returns a new department", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);
    vi.mocked(createDepartment).mockResolvedValue({
      id: "dept-new",
      account_id: "acct-1",
      name: "Sales",
      description: "Handles sales inquiries",
      created_at: "2026-01-01T00:00:00Z",
      archived_at: null,
    });

    const req = new Request("http://localhost/api/departments", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Sales", description: "Handles sales inquiries" }),
    });

    const res = await POST(req);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.department.name).toBe("Sales");
  });

  it("returns 400 when name is missing", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);

    const req = new Request("http://localhost/api/departments", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description: "No name provided" }),
    });

    const res = await POST(req);
    expect(res.status).toBe(400);
  });

  it("returns 400 when name is empty", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);

    const req = new Request("http://localhost/api/departments", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "" }),
    });

    const res = await POST(req);
    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid JSON", async () => {
    vi.mocked(requireRole).mockResolvedValue(mockCtx);

    const req = new Request("http://localhost/api/departments", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-json",
    });

    const res = await POST(req);
    expect(res.status).toBe(400);
  });
});
