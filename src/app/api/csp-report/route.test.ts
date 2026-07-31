import { describe, expect, it, vi, afterEach } from "vitest";
import { POST, GET } from "./route";

// The CSP report endpoint is intentionally unauthenticated — browsers
// POST violation reports without credentials. It must accept a real
// CSP report payload, log it, and respond 204; junk input gets 400.
// A GET (or any non-POST) is not supported.

describe("POST /api/csp-report", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("accepts a valid CSP violation report and returns 204", async () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const req = new Request("http://localhost/api/csp-report", {
      method: "POST",
      headers: { "Content-Type": "application/csp-report" },
      body: JSON.stringify({
        "csp-report": {
          "document-uri": "https://app.test/inbox",
          "violated-directive": "script-src",
          "effective-directive": "script-src",
          "blocked-uri": "https://evil.example/x.js",
          "source-file": "https://app.test/inbox",
          "line-number": 42,
        },
      }),
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
});

describe("GET /api/csp-report", () => {
  it("is not supported — returns 405", async () => {
    const res = await GET();
    expect(res.status).toBe(405);
  });
});
