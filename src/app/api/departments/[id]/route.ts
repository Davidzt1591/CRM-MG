// ============================================================
// /api/departments/[id]
//
//   GET    — get department detail.              Any member of the account.
//   PATCH  — update department.                  Admin+.
//   DELETE — archive department.                 Admin+.
//
// All endpoints use Zod validation, rate limiting, audit logging.
// ============================================================

import { NextResponse } from "next/server";
import { z } from "zod";

import { requireRole, getCurrentAccount, toErrorResponse } from "@/lib/auth/account";
import {
  checkRateLimit,
  rateLimitResponse,
  RATE_LIMITS,
} from "@/lib/rate-limit";
import {
  getDepartment,
  updateDepartment,
  archiveDepartment,
} from "@/lib/departments";
import { recordAuditEvent } from "@/lib/audit";
import { validationErrorResponse } from "@/lib/validation";

const updateDepartmentSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  description: z.string().max(500).nullable().optional(),
});

/** Parse a JSON body with a Zod schema, returning the parsed data
 *  or a 400 NextResponse on failure. Bypasses parseValidatedBody
 *  because route handlers receive `Request`, not `NextRequest`. */
async function parseBody<T>(
  request: Request,
  schema: z.ZodSchema<T>,
): Promise<T | NextResponse> {
  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
  const result = schema.safeParse(raw);
  if (!result.success) {
    return validationErrorResponse(result.error.issues);
  }
  return result.data;
}

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const ctx = await getCurrentAccount();
    const { id } = await params;

    const department = await getDepartment(id);
    if (!department) {
      return NextResponse.json(
        { error: "Department not found" },
        { status: 404 },
      );
    }

    return NextResponse.json({ department });
  } catch (err) {
    return toErrorResponse(err);
  }
}

export async function PATCH(
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

    const body = await parseBody(request, updateDepartmentSchema);
    if (body instanceof NextResponse) return body;

    const old = await getDepartment(id);
    if (!old) {
      return NextResponse.json(
        { error: "Department not found" },
        { status: 404 },
      );
    }

    const department = await updateDepartment(id, body);

    await recordAuditEvent({
      accountId: ctx.accountId,
      userId: ctx.userId,
      action: "department.update",
      targetType: "department",
      targetId: id,
      oldValues: { name: old.name, description: old.description },
      newValues: { name: department.name, description: department.description },
    });

    return NextResponse.json({ department });
  } catch (err) {
    return toErrorResponse(err);
  }
}

export async function DELETE(
  _request: Request,
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

    await archiveDepartment(id);

    await recordAuditEvent({
      accountId: ctx.accountId,
      userId: ctx.userId,
      action: "department.archive",
      targetType: "department",
      targetId: id,
      oldValues: { name: department.name },
    });

    return NextResponse.json({ ok: true });
  } catch (err) {
    return toErrorResponse(err);
  }
}
