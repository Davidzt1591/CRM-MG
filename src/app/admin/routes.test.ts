import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { ADMIN_NAV_ITEMS } from "@/lib/admin/nav";

const APP_DIR = join(process.cwd(), "src", "app");

/**
 * Guards the admin route wiring. The admin area must live under a real
 * `/admin` path — a `(admin)` route group would serve unprefixed URLs
 * (/departments, /whatsapp, /salesforce) while every nav link targets
 * /admin/*, producing 404s. These tests fail loudly if the group
 * structure regresses.
 */
describe("admin route wiring", () => {
  it("serves admin pages from a real /admin path, not a route group", () => {
    expect(existsSync(join(APP_DIR, "admin", "page.tsx"))).toBe(true);
    expect(existsSync(join(APP_DIR, "admin", "departments", "page.tsx"))).toBe(
      true,
    );
    expect(
      existsSync(join(APP_DIR, "admin", "departments", "[id]", "page.tsx")),
    ).toBe(true);
    expect(existsSync(join(APP_DIR, "admin", "whatsapp", "page.tsx"))).toBe(
      true,
    );
    expect(existsSync(join(APP_DIR, "admin", "salesforce", "page.tsx"))).toBe(
      true,
    );
    // The old route group must be gone — no residual (admin) directory.
    expect(existsSync(join(APP_DIR, "(admin)"))).toBe(false);
  });

  it("removes the root / collision — the admin entry lives under /admin", () => {
    // Root "/" is served by the single root page.tsx (dashboard redirect).
    expect(existsSync(join(APP_DIR, "page.tsx"))).toBe(true);
    // A (admin)/page.tsx would ALSO map to "/" — ambiguous with root.
    expect(existsSync(join(APP_DIR, "(admin)", "page.tsx"))).toBe(false);
  });

  it("every admin nav item targets the /admin prefix", () => {
    expect(ADMIN_NAV_ITEMS.length).toBeGreaterThan(0);
    for (const item of ADMIN_NAV_ITEMS) {
      expect(
        item.href.startsWith("/admin/"),
        `${item.href} must live under the /admin prefix`,
      ).toBe(true);
    }
  });

  it("exposes an audit-logs entry so the MCRM-24 viewer is reachable", () => {
    const hrefs = ADMIN_NAV_ITEMS.map((i) => i.href);
    expect(hrefs).toContain("/admin/audit-logs");
  });
});
