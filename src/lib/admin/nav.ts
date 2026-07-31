/**
 * Admin area navigation.
 *
 * Single source of truth for the admin sub-navigation so the sidebar,
 * the admin layout nav, and tests all agree on where the admin pages
 * live. Every href here MUST start with `/admin` — the admin pages are
 * served from `src/app/admin/`, not a route group, so any other prefix
 * would 404.
 */
export interface AdminNavItem {
  /** Route path under the /admin prefix. */
  href: string;
  /** next-intl key inside the `Admin.nav` namespace. */
  labelKey: string;
  /** Lucide icon component name (resolved by the consuming UI). */
  icon: string;
}

export const ADMIN_NAV_ITEMS: AdminNavItem[] = [
  { href: "/admin/departments", labelKey: "departments", icon: "GitBranch" },
  { href: "/admin/whatsapp", labelKey: "whatsapp", icon: "MessageSquare" },
  { href: "/admin/salesforce", labelKey: "salesforce", icon: "Zap" },
  { href: "/admin/audit-logs", labelKey: "auditLogs", icon: "Shield" },
];
