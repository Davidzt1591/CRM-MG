"use client";

import { useAuth } from "@/hooks/use-auth";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import { useEffect } from "react";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";
import { ADMIN_NAV_ITEMS } from "@/lib/admin/nav";
import { GitBranch, MessageSquare, Shield, Zap } from "lucide-react";

// Icon map keyed by the string names in ADMIN_NAV_ITEMS — keeps the
// shared nav module dependency-free (pure data, unit-testable) while
// the layout resolves the Lucide components it needs to render.
const NAV_ICONS = {
  GitBranch,
  MessageSquare,
  Shield,
  Zap,
} as const;

export default function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { accountRole, profileLoading, loading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const t = useTranslations("Admin");

  useEffect(() => {
    if (!loading && !profileLoading) {
      if (!accountRole || (accountRole !== "owner" && accountRole !== "admin")) {
        router.push("/dashboard");
      }
    }
  }, [accountRole, profileLoading, loading, router]);

  if (loading || profileLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <p className="text-sm text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  if (!accountRole || (accountRole !== "owner" && accountRole !== "admin")) {
    return null;
  }

  return (
    <div className="flex min-h-screen flex-col">
      {/* Admin sub-navigation — every entry lives under /admin (see
          src/lib/admin/nav.ts). Replaces the old route-group layout that
          rendered children with no way to reach the admin pages. */}
      <nav
        aria-label="Admin"
        className="flex shrink-0 items-center gap-1 overflow-x-auto border-b border-border bg-card px-4 py-2"
      >
        {ADMIN_NAV_ITEMS.map((item) => {
          const Icon = NAV_ICONS[item.icon as keyof typeof NAV_ICONS];
          const isActive =
            pathname === item.href || pathname.startsWith(`${item.href}/`);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4" />
              {t(`nav.${item.labelKey}`)}
            </Link>
          );
        })}
      </nav>
      <main className="flex-1">{children}</main>
    </div>
  );
}
