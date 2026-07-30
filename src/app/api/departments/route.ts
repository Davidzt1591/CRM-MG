// ============================================================
// /api/departments
//
//   GET  — list departments for current account (admin sees all,
//          agent sees assigned).             Any authenticated user.
//   POST — create a department.              Admin+.
//
// Both endpoints use Zod for body validation, audit logging for
// mutations, and require authentication via requireRole.
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
  listDepartments,
  createDepartment,
} from "@/lib/departments";
import { recordAuditEvent } from "@/lib/audit";
import { validationErrorResponse } from "@/lib/validation";

const createDepartmentSchema = z.object({
  name: z.string().min(1, "Name is required").max(100),
  description: z.string().max(500).optional(),
});

export async function GET() {
  try {
    const ctx = await requireRole("agent");
    const departments = await listDepartments();
    return NextResponse.json({ departments });
  } catch (err) {
    return toErrorResponse(err);
  }
}

export async function POST(request: Request) {
  try {
    const ctx = await requireRole("admin");

    const limit = checkRateLimit(
      `admin:department:${ctx.userId}`,
      RATE_LIMITS.adminAction,
    );
    if (!limit.success) return rateLimitResponse(limit);

    // Parse and validate the request body manually
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const parsed = createDepartmentSchema.safeParse(rawBody);
    if (!parsed.success) {
      return validationErrorResponse(parsed.error.issues);
    }
    const body = parsed.data;

    const department = await createDepartment(body);

    await recordAuditEvent({
      accountId: ctx.accountId,
      userId: ctx.userId,
      action: "department.create",
      targetType: "department",
      targetId: department.id,
      newValues: { name: department.name, description: department.description },
    });

    return NextResponse.json({ department }, { status: 201 });
  } catch (err) {
    return toErrorResponse(err);
  }
}
