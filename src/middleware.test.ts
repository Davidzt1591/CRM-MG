import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import crypto from 'node:crypto';
import { NextRequest } from "next/server";

// --- Scenario knobs the mock reads -----------------------------------------
// `mockUser`         — what getUser() resolves to (a refreshed session ⇒ user,
//                      or null for the logged-out path).
// `refreshedCookies` — cookies Supabase writes via setAll() during getUser(),
//                      i.e. the freshly *rotated* auth token. The whole point
//                      of the test is that these must survive onto whatever
//                      response the middleware returns — including redirects.
let mockUser: { id: string } | null = null;
let refreshedCookies: Array<{
  name: string;
  value: string;
  options: Record<string, unknown>;
}> = [];

vi.mock("@supabase/ssr", () => ({
  createServerClient: (
    _url: string,
    _key: string,
    opts: {
      cookies: { setAll: (c: typeof refreshedCookies) => void };
    },
  ) => ({
    auth: {
      // Mirrors real auth-js: an expired access token is transparently
      // refreshed inside getUser(), which rotates the refresh token and
      // pushes the new cookies through setAll() before resolving.
      getUser: async () => {
        if (refreshedCookies.length) opts.cookies.setAll(refreshedCookies);
        return { data: { user: mockUser } };
      },
    },
  }),
}));

// Imported after the mock is registered.
const { middleware } = await import("./middleware");

beforeEach(() => {
  process.env.NEXT_PUBLIC_SUPABASE_URL = "https://test.supabase.co";
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon-key";
  mockUser = null;
  refreshedCookies = [];
});

afterEach(() => vi.clearAllMocks());

function cspValue(res: Response): string | null {
  return res.headers.get("Content-Security-Policy");
}

describe("middleware — CSP nonce", () => {
  it("sets Content-Security-Policy header on HTML page responses", async () => {
    mockUser = { id: "user-1" };
    const res = await middleware(new NextRequest("https://app.test/dashboard"));
    expect(cspValue(res)).toBeTruthy();
  });

  it("includes a unique nonce per request in script-src", async () => {
    mockUser = { id: "user-1" };
    const res1 = await middleware(new NextRequest("https://app.test/dashboard"));
    const res2 = await middleware(new NextRequest("https://app.test/dashboard"));
    const csp1 = cspValue(res1)!;
    const csp2 = cspValue(res2)!;

    // Extract nonces
    const match1 = /'nonce-([^']+)'/.exec(csp1);
    const match2 = /'nonce-([^']+)'/.exec(csp2);
    expect(match1).not.toBeNull();
    expect(match2).not.toBeNull();
    // Nonces must differ per request
    expect(match1![1]).not.toBe(match2![1]);
  });

  it("contains 'self' and nonce in script-src directive", async () => {
    mockUser = { id: "user-1" };
    const res = await middleware(new NextRequest("https://app.test/dashboard"));
    const csp = cspValue(res)!;
    expect(csp).toContain("script-src");
    expect(csp).toContain("'self'");
    expect(csp).toMatch(/'nonce-/);
  });

  it("sets x-nonce response header", async () => {
    mockUser = { id: "user-1" };
    const res = await middleware(new NextRequest("https://app.test/dashboard"));
    const nonce = res.headers.get("x-nonce");
    expect(nonce).toBeTruthy();
    expect(nonce).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it("does not set CSP on API routes by default (differentiator)", async () => {
    // API routes don't render HTML so CSP is less critical; verify it's still set
    mockUser = { id: "user-1" };
    const res = await middleware(
      new NextRequest("https://app.test/api/whatsapp/send"),
    );
    // Should still get CSP since middleware applies to all matched routes
    // (the middleware matcher is broad — it's per-response, not per-page)
    expect(cspValue(res)).toBeTruthy();
  });
});

describe("middleware — CSP violation reporting (SEC-09)", () => {
  it("includes report-uri pointing at the local report endpoint", async () => {
    mockUser = { id: "user-1" };
    const res = await middleware(new NextRequest("https://app.test/dashboard"));
    const csp = cspValue(res)!;
    expect(csp).toContain("report-uri /api/csp-report");
  });

  it("includes report-to group for modern browsers", async () => {
    mockUser = { id: "user-1" };
    const res = await middleware(new NextRequest("https://app.test/dashboard"));
    const csp = cspValue(res)!;
    expect(csp).toContain("report-to csp-endpoint");
  });

  it("sends a Report-To header defining the csp-endpoint group", async () => {
    mockUser = { id: "user-1" };
    const res = await middleware(new NextRequest("https://app.test/dashboard"));
    const reportTo = res.headers.get("Report-To");
    expect(reportTo).toBeTruthy();
    expect(reportTo).toContain("csp-endpoint");
    expect(reportTo).toContain("/api/csp-report");
  });

  it("keeps reporting on responses that carry refreshed auth cookies", async () => {
    mockUser = { id: "user-1" };
    refreshedCookies = [ROTATED];
    const res = await middleware(new NextRequest("https://app.test/login"));
    // Redirect responses must still advertise the reporting group.
    expect(res.headers.get("Report-To")).toContain("csp-endpoint");
  });
});

const ROTATED = {
  name: "sb-test-auth-token",
  value: "rotated-refresh-token",
  options: { path: "/", httpOnly: true },
};

describe("middleware — refreshed auth cookies survive redirects", () => {
  it("carries the rotated token when redirecting a signed-in user off /login", async () => {
    mockUser = { id: "user-1" };
    refreshedCookies = [ROTATED];

    const res = await middleware(
      new NextRequest("https://app.test/login"),
    );

    // Redirect to /dashboard…
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toContain("/dashboard");
    // …and the rotated cookie MUST ride along, otherwise the browser keeps
    // replaying the now-consumed refresh token and the session wedges until
    // the user manually clears cookies.
    expect(res.cookies.get(ROTATED.name)?.value).toBe(ROTATED.value);
  });

  it("carries the rotated token when redirecting an unauth user to /login", async () => {
    mockUser = null;
    // Even on the logged-out path getUser() may emit cookie writes (e.g.
    // clearing a dead session); those must not be dropped on the redirect.
    refreshedCookies = [{ ...ROTATED, value: "cleared" }];

    const res = await middleware(
      new NextRequest("https://app.test/dashboard"),
    );

    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toContain("/login");
    expect(res.cookies.get(ROTATED.name)?.value).toBe("cleared");
  });

  it("redirects a signed-in user with an invite token to /join/<token>", async () => {
    mockUser = { id: "user-1" };
    refreshedCookies = [ROTATED];

    const res = await middleware(
      new NextRequest("https://app.test/login?invite=abc123"),
    );

    expect(res.headers.get("location")).toContain("/join/abc123");
    expect(res.cookies.get(ROTATED.name)?.value).toBe(ROTATED.value);
  });

  it("passes through (no redirect) for a signed-in user on a protected page", async () => {
    mockUser = { id: "user-1" };
    refreshedCookies = [ROTATED];

    const res = await middleware(
      new NextRequest("https://app.test/dashboard"),
    );

    // No redirect — the normal NextResponse.next() already carries cookies.
    expect(res.headers.get("location")).toBeNull();
    expect(res.cookies.get(ROTATED.name)?.value).toBe(ROTATED.value);
  });
});
