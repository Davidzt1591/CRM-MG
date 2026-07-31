// ============================================================
// /api/admin/audit-logs
//
//   GET — list the account's audit trail entries. Owner/admin only.
//
// Returns the most recent entries first (created_at DESC), scoped to
// the caller's account. The 037 RLS policy already limits reads to
// owner/admin profiles of the same account; the explicit account_id
// filter keeps that discipline visible and cheap. Optional ?limit=
// (default 100, max 500) trims large trails.
// ============================================================

import { NextResponse } from "next/server";

import { requireRole, toErrorResponse } from "@/lib/auth/account";

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

const AUDIT_LOG_COLUMNS =
  "id, user_id, action, target_type, target_id, old_values, new_values, ip_address, created_at";

export async function GET(request: Request) {
  try {
    const ctx = await requireRole("admin");

    // Optional limit with strict bounds — junk params get 400, never
    // a full-table scan.
    const url = new URL(request.url);
    const rawLimit = url.searchParams.get("limit");
    let limit = DEFAULT_LIMIT;
    if (rawLimit !== null) {
      const parsed = Number(rawLimit);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > MAX_LIMIT) {
        return NextResponse.json(
          { error: "Invalid limit (must be an integer between 1 and 500)" },
          { status: 400 },
        );
      }
      limit = parsed;
    }

    const { data, error } = await ctx.supabase
      .from("audit_logs")
      .select(AUDIT_LOG_COLUMNS)
      .eq("account_id", ctx.accountId)
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) {
      console.error("[audit-logs] fetch error:", error);
      return NextResponse.json(
        { error: "Failed to fetch audit logs" },
        { status: 500 },
      );
    }

    return NextResponse.json({ logs: data ?? [] });
  } catch (err) {
    return toErrorResponse(err);
  }
}
