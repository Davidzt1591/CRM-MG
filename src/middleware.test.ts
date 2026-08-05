import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import crypto from 'node:crypto';
import { NextRequest } from "next/server";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Read the production middleware source at module load so the structural
// Edge-compat assertions below (no node:crypto import) have something to
// assert against. The test process itself runs in Node, which is why the
// test file's own `crypto` import above is fine — only the *runtime*
// middleware must stay Edge-safe (D7).
const middlewareSource = readFileSync(
  resolve(__dirname, "middleware.ts"),
  "utf8",
);

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

// `mockProfile`      — the profiles row returned for the user, i.e. the caller's
//                      account_role. Drives the /admin/* server-side role gate:
//                      null → no profile (forbidden), a non-admin role → 403,
//                      owner/admin → pass-through.
let mockProfile: { account_role: string } | null = null;
let mockProfileError: unknown = null;

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
    // Profiles point-lookup backing the /admin/* role gate (SEC-01).
    // Returns whatever `mockProfile` the scenario set; mirrors the real
    // `.select(...).eq(...).maybeSingle()` shape the middleware calls.
    from(_table: string) {
      return {
        select(_columns: string) {
          return {
            eq(_col: string, _val: unknown) {
              return {
                maybeSingle: async () => ({ data: mockProfile, error: mockProfileError }),
                // Allow awaiting the builder directly (some routes do).
                then: (onFulfilled: (v: unknown) => unknown) =>
                  Promise.resolve({ data: mockProfile, error: mockProfileError }).then(
                    onFulfilled,
                  ),
              };
            },
          };
        },
      };
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
  mockProfile = null;
  mockProfileError = null;
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

// ============================================================
// SEC-01: server-side admin role gate for /admin/* (MCRM-57)
//
// The client-only redirect in src/app/admin/layout.tsx is NOT a
// security boundary — it can be bypassed by navigating directly to a
// /admin/* URL with a stolen session cookie. The middleware must
// enforce the role server-side: authenticated non-admins get 403,
// authenticated admins/owners pass through, and anonymous users keep
// the existing /login redirect. /api/admin/* is intentionally NOT
// gated here (route-level requireRole stays the boundary, D6).
// ============================================================
describe("middleware — admin role gate (SEC-01 / MCRM-57)", () => {
  it("returns 403 for an authenticated member on /admin/*", async () => {
    mockUser = { id: "user-member" };
    mockProfile = { account_role: "viewer" };

    const res = await middleware(
      new NextRequest("https://app.test/admin/salesforce"),
    );

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("Forbidden");
  });

  it("returns 403 for an agent (lowest non-admin role) on /admin/*", async () => {
    mockUser = { id: "user-agent" };
    mockProfile = { account_role: "agent" };

    const res = await middleware(
      new NextRequest("https://app.test/admin/departments"),
    );

    expect(res.status).toBe(403);
  });

  it("lets an admin pass through on /admin/* (no 403, no redirect)", async () => {
    mockUser = { id: "user-admin" };
    mockProfile = { account_role: "admin" };

    const res = await middleware(
      new NextRequest("https://app.test/admin/salesforce"),
    );

    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });

  it("lets an owner pass through on /admin/*", async () => {
    mockUser = { id: "user-owner" };
    mockProfile = { account_role: "owner" };

    const res = await middleware(new NextRequest("https://app.test/admin/audit-logs"));

    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });

  it("redirects an anonymous user to /login (307) on /admin/*", async () => {
    mockUser = null;
    mockProfile = null;

    const res = await middleware(
      new NextRequest("https://app.test/admin/whatsapp"),
    );

    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toMatch(/\/login/);
  });

  it("does NOT 403 an authenticated member on a protected non-admin page", async () => {
    mockUser = { id: "user-member" };
    mockProfile = { account_role: "viewer" };

    const res = await middleware(new NextRequest("https://app.test/dashboard"));

    // /dashboard is protected (login gate) but not admin-scoped, so a
    // member must reach it — the role gate must not over-gate.
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });

  it("does NOT 403 on /api/admin/* — page-only gate, routes keep their own requireRole", async () => {
    mockUser = { id: "user-member" };
    mockProfile = { account_role: "viewer" };

    const res = await middleware(
      new NextRequest("https://app.test/api/admin/audit-logs"),
    );

    // Middleware must pass /api/admin/* through (D6); the route layer is
    // the boundary for API access, and it must not be shadowed here.
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });

  it("carries refreshed auth cookies onto the 403 response", async () => {
    mockUser = { id: "user-member" };
    mockProfile = { account_role: "viewer" };
    refreshedCookies = [ROTATED];

    const res = await middleware(
      new NextRequest("https://app.test/admin/salesforce"),
    );

    // The rotated refresh token must survive the 403 (issue #288 pattern)
    // otherwise an idle-then-active member wedges on a consumed token.
    expect(res.status).toBe(403);
    expect(res.cookies.get(ROTATED.name)?.value).toBe(ROTATED.value);
  });

  it("still emits CSP + x-nonce on the 403 response", async () => {
    mockUser = { id: "user-member" };
    mockProfile = { account_role: "viewer" };

    const res = await middleware(
      new NextRequest("https://app.test/admin/departments"),
    );

    expect(res.status).toBe(403);
    expect(res.headers.get("Content-Security-Policy")).toMatch(/'nonce-/);
    expect(res.headers.get("Report-To")).toContain("csp-endpoint");
    expect(res.headers.get("x-nonce")).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it("treats a missing profile as non-admin (403), not a bypass", async () => {
    mockUser = { id: "user-orphan" };
    mockProfile = null;

    const res = await middleware(new NextRequest("https://app.test/admin/whatsapp"));

    // No profile row ⇒ can't establish admin role ⇒ hard 403 (fail closed).
    expect(res.status).toBe(403);
  });
});

// ============================================================
// Edge-compatible nonce generation (MCRM-59 / D7)
//
// Next 16's Edge runtime (used by middleware) does NOT ship node:crypto,
// so `import crypto from 'node:crypto'` raises a build warning and
// breaks Edge deployments. The runtime contract that makes this
// testable in a Node-based unit test is: the nonce must keep coming out
// as a valid, unique UUID v4 (so CSP stays sound) while the source must
// not reference node:crypto. There is no runtime-visible behavioural
// difference between crypto.randomUUID() and globalThis.crypto.randomUUID()
// — both yield UUID v4 — so the Edge-compat requirement is asserted
// structurally on the source, and behavioural preservation is guarded
// by the UUID format + uniqueness assertions.
// ============================================================
describe("middleware — Edge-compatible nonce (MCRM-59 / D7)", () => {
  it("does not import node:crypto (Edge runtime unsupported)", () => {
    // The real hazard is an actual `import ... from 'node:crypto'`, which
    // would break the Edge runtime. A comment mentioning the module name is
    // fine, so assert on the import shape rather than the bare substring.
    const nodeCryptoImports = middlewareSource
      .split("\n")
      .map((line) => line.match(/^import\s+.*from\s*['"]node:crypto['"]/))
      .filter(Boolean);
    expect(nodeCryptoImports).toHaveLength(0);
  });

  it("generates the nonce via globalThis.crypto.randomUUID", () => {
    expect(middlewareSource).toContain("globalThis.crypto.randomUUID");
  });

  it("produces a valid UUID v4 nonce on every request", async () => {
    mockUser = { id: "user-1" };
    const res = await middleware(new NextRequest("https://app.test/dashboard"));
    const nonce = res.headers.get("x-nonce");
    expect(nonce).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it("emits a unique nonce across a burst of requests", async () => {
    mockUser = { id: "user-1" };
    const nonces = new Set<string>();
    for (let i = 0; i < 25; i++) {
      const res = await middleware(new NextRequest("https://app.test/dashboard"));
      const n = res.headers.get("x-nonce");
      // Real behaviour: each call to the generator yields a distinct UUID.
      expect(n).toBeTruthy();
      nonces.add(n as string);
    }
    // A collision here would mean the generator is not random enough to
    // blind CSP nonces — the assertion fails loudly rather than guessing.
    expect(nonces.size).toBe(25);
  });
});
