// ============================================================
// /api/departments/[id]/members
//
//   GET    — list department members.              Admin+.
//   POST   — assign agent to department.           Admin+.
//   DELETE — remove agent from department.         Admin+.
//
// Uses Zod validation, rate limiting, audit logging.
// ============================================================

import { NextResponse } from "next/server";
import { z } from "zod";

import { requireRole, toErrorResponse } from "@/lib/auth/account";
import {
  checkRateLimit,
  rateLimitResponse,
  RATE_LIMITS,
} from "@/lib/rate-limit";
import {
  getDepartment,
  getDepartmentMembers,
  assignToDepartment,
  removeFromDepartment,
} from "@/lib/departments";
import { recordAuditEvent } from "@/lib/audit";

const assignMemberSchema = z.object({
  profileId: z.string().uuid("Invalid profile ID"),
});

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const ctx = await requireRole("admin");
    const { id } = await params;

    const department = await getDepartment(id);
    if (!department) {
      return NextResponse.json(
        { error: "Department not found" },
        { status: 404 },
      );
    }

    const members = await getDepartmentMembers(id);
    return NextResponse.json({ members });
  } catch (err) {
    return toErrorResponse(err);
  }
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const ctx = await requireRole("admin");
    const { id } = await params;

    const limit = checkRateLimit(
      `admin:department:${ctx.userId}`,
      RATE_LIMITS.adminAction,
    );
    if (!limit.success) return rateLimitResponse(limit);

    const department = await getDepartment(id);
    if (!department) {
      return NextResponse.json(
        { error: "Department not found" },
        { status: 404 },
      );
    }

    let body: z.infer<typeof assignMemberSchema>;
    try {
      const raw = await request.json();
      const result = assignMemberSchema.safeParse(raw);
      if (!result.success) {
        return NextResponse.json(
          {
            error: "Validation failed",
            details: result.error.issues.map((i) => ({
              path: i.path.join("."),
              message: i.message,
            })),
          },
          { status: 400 },
        );
      }
      body = result.data;
    } catch {
      return NextResponse.json(
        { error: "Invalid JSON body" },
        { status: 400 },
      );
    }

    await assignToDepartment(body.profileId, id);

    await recordAuditEvent({
      accountId: ctx.accountId,
      userId: ctx.userId,
      action: "department.assign",
      targetType: "department",
      targetId: id,
      newValues: { profileId: body.profileId },
    });

    return NextResponse.json({ ok: true });
  } catch (err) {
    return toErrorResponse(err);
  }
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const ctx = await requireRole("admin");
    const { id } = await params;

    const limit = checkRateLimit(
      `admin:department:${ctx.userId}`,
      RATE_LIMITS.adminAction,
    );
    if (!limit.success) return rateLimitResponse(limit);

    const department = await getDepartment(id);
    if (!department) {
      return NextResponse.json(
        { error: "Department not found" },
        { status: 404 },
      );
    }

    const url = new URL(request.url);
    const profileId = url.searchParams.get("profileId");
    if (!profileId) {
      return NextResponse.json(
        { error: "profileId query parameter is required" },
        { status: 400 },
      );
    }

    await removeFromDepartment(profileId, id);

    await recordAuditEvent({
      accountId: ctx.accountId,
      userId: ctx.userId,
      action: "department.unassign",
      targetType: "department",
      targetId: id,
      oldValues: { profileId },
    });

    return NextResponse.json({ ok: true });
  } catch (err) {
    return toErrorResponse(err);
  }
}
