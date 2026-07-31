import { describe, expect, it, vi, beforeEach } from "vitest";
import { POST, GET } from "./route";

// The CSP report endpoint is intentionally unauthenticated — browsers
// POST violation reports without credentials. It must accept a real
// CSP report payload, log it, and respond 204; junk input gets 400,
// oversized bodies get 413, floods get 429 (per-IP rate limit), and a
// GET (or any non-POST) is not supported. Log output must be
// sanitized: attacker-controlled fields are truncated and stripped of
// control characters so a crafted report can't inject log lines.

const { checkRateLimit, rateLimitResponse } = vi.hoisted(() => ({
  checkRateLimit: vi.fn(),
  rateLimitResponse: vi.fn(),
}));

vi.mock("@/lib/rate-limit", () => ({
  checkRateLimit: (key: string, opts: unknown) => checkRateLimit(key, opts),
  rateLimitResponse: (result: unknown) => rateLimitResponse(result),
  RATE_LIMITS: { cspReport: { limit: 60, windowMs: 60_000 } },
}));

function makeLegacyReport(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    "csp-report": {
      "document-uri": "https://app.test/inbox",
      "violated-directive": "script-src",
      "effective-directive": "script-src",
      "blocked-uri": "https://evil.example/x.js",
      "source-file": "https://app.test/inbox",
      "line-number": 42,
      ...overrides,
    },
  });
}

/** A Request whose body is a stream, so Content-Length is absent. */
function streamRequest(body: string): Request {
  const encoder = new TextEncoder();
  return new Request("http://localhost/api/csp-report", {
    method: "POST",
    headers: { "Content-Type": "application/csp-report" },
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(body));
        controller.close();
      },
    }),
    // undici requires the duplex flag when the body is a stream.
    duplex: "half",
  } as RequestInit);
}

describe("POST /api/csp-report", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    checkRateLimit.mockReturnValue({
      success: true,
      remaining: 59,
      reset: 0,
      limit: 60,
    });
    rateLimitResponse.mockReturnValue(
      new Response(JSON.stringify({ error: "Rate limit exceeded" }), {
        status: 429,
      }),
    );
  });

  it("accepts a valid CSP violation report and returns 204", async () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const req = new Request("http://localhost/api/csp-report", {
      method: "POST",
      headers: { "Content-Type": "application/csp-report" },
      body: makeLegacyReport(),
    });

    const res = await POST(req);
    expect(res.status).toBe(204);
    // The report is logged so operators can inspect violations.
    expect(spy).toHaveBeenCalled();
    expect(spy.mock.calls[0].join(" ")).toContain("script-src");
    spy.mockRestore();
  });

  it("accepts the browser's raw-report shape (report-to format) too", async () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const req = new Request("http://localhost/api/csp-report", {
      method: "POST",
      headers: { "Content-Type": "application/reports+json" },
      body: JSON.stringify([
        {
          type: "csp-violation",
          body: { "violated-directive": "img-src", "blocked-uri": "data:image/x" },
        },
      ]),
    });

    const res = await POST(req);
    expect(res.status).toBe(204);
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it("rejects invalid JSON with 400", async () => {
    const req = new Request("http://localhost/api/csp-report", {
      method: "POST",
      headers: { "Content-Type": "application/csp-report" },
      body: "not-json",
    });

    const res = await POST(req);
    expect(res.status).toBe(400);
  });

  it("rejects a body that is not a report object with 400", async () => {
    const req = new Request("http://localhost/api/csp-report", {
      method: "POST",
      headers: { "Content-Type": "application/csp-report" },
      body: JSON.stringify({ hello: "world" }),
    });

    const res = await POST(req);
    expect(res.status).toBe(400);
  });

  it("returns 413 when Content-Length advertises an oversized body", async () => {
    const req = new Request("http://localhost/api/csp-report", {
      method: "POST",
      headers: { "Content-Type": "application/csp-report", "Content-Length": "500000" },
      body: null,
    });

    const res = await POST(req);
    expect(res.status).toBe(413);
  });

  it("returns 413 when the body exceeds the size cap (no Content-Length)", async () => {
    // 200 KB of valid report JSON, streamed so the request carries no
    // Content-Length header — the route must still refuse to process it.
    const huge = makeLegacyReport({
      "blocked-uri": `https://evil.example/${"x".repeat(200 * 1024)}`,
    });
    const req = streamRequest(huge);

    const res = await POST(req);
    expect(res.status).toBe(413);
  });

  it("returns 429 when the per-IP rate limit is exhausted", async () => {
    checkRateLimit.mockReturnValue({
      success: false,
      remaining: 0,
      reset: Date.now() + 60_000,
      limit: 60,
    });
    const req = new Request("http://localhost/api/csp-report", {
      method: "POST",
      headers: { "Content-Type": "application/csp-report" },
      body: makeLegacyReport(),
    });

    const res = await POST(req);
    expect(res.status).toBe(429);
    // The limit check must key on the client IP, not a fixed key.
    expect(checkRateLimit).toHaveBeenCalledWith(
      expect.stringContaining("csp-report:"),
      expect.objectContaining({ limit: 60 }),
    );
  });

  it("sanitizes log output: strips control chars and truncates long fields", async () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const longValue = "x".repeat(500);
    const req = new Request("http://localhost/api/csp-report", {
      method: "POST",
      headers: { "Content-Type": "application/csp-report" },
      body: makeLegacyReport({
        "blocked-uri": `https://evil.example/${longValue}\u001b[31m`,
        "source-file": "https://app.test/inbox\nFAKE LOG LINE",
      }),
    });

    const res = await POST(req);
    expect(res.status).toBe(204);

    const logged = spy.mock.calls.map((c) => String(c[0])).join("\n");
    // No control characters (escapes, newlines) may reach the log — a
    // crafted report can't forge a new log line or an ANSI escape.
    expect(logged).not.toMatch(/[\u0000-\u001F\u007F-\u009F]/);
    // The whole entry is a single line (no embedded newline anywhere).
    expect(logged).not.toContain("\n");
    // Long attacker-controlled values are truncated, not echoed whole.
    expect(logged).not.toContain(longValue);
    spy.mockRestore();
  });
});

describe("GET /api/csp-report", () => {
  it("is not supported — returns 405", async () => {
    const res = await GET();
    expect(res.status).toBe(405);
  });
});
