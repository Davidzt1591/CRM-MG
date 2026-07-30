"use client";

import { useAuth } from "@/hooks/use-auth";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { accountRole, profileLoading, loading } = useAuth();
  const router = useRouter();

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

  return <>{children}</>;
}
