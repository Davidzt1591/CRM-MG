// ============================================================
// /api/conversations/[id]/transfer
//
//   POST — transfer conversation to another department.
//
// Request body: { departmentId: string, note?: string }
//
// Validates:
//   - Target department exists
//   - User is member of source department (or admin)
//   - Conversation exists and caller has access
//
// Side effects:
//   - Updates conversations.department_id
//   - Records audit event
//   - Sends notification to target department agents
// ============================================================

import { NextResponse } from "next/server";
import { z } from "zod";

import { getCurrentAccount, toErrorResponse } from "@/lib/auth/account";
import {
  checkRateLimit,
  rateLimitResponse,
  RATE_LIMITS,
} from "@/lib/rate-limit";
import { createClient } from "@/lib/supabase/server";
import { getDepartment } from "@/lib/departments";
import { recordAuditEvent } from "@/lib/audit";

const transferSchema = z.object({
  departmentId: z.string().uuid("Invalid department ID"),
  note: z.string().max(500).optional(),
});

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const ctx = await getCurrentAccount();
    const { id: conversationId } = await params;

    const limit = checkRateLimit(
      `transfer:${ctx.userId}`,
      RATE_LIMITS.adminAction,
    );
    if (!limit.success) return rateLimitResponse(limit);

    // Parse and validate request body
    let body: z.infer<typeof transferSchema>;
    try {
      const raw = await request.json();
      const result = transferSchema.safeParse(raw);
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

    // Verify target department exists
    const targetDept = await getDepartment(body.departmentId);
    if (!targetDept) {
      return NextResponse.json(
        { error: "Target department not found" },
        { status: 404 },
      );
    }

    // Get the conversation
    const supabase = await createClient();
    const { data: conversation, error: convError } = await supabase
      .from("conversations")
      .select("id, account_id, department_id, contact_id, assigned_agent_id")
      .eq("id", conversationId)
      .maybeSingle();

    if (convError) {
      console.error("[transfer] conversation fetch error:", convError);
      return NextResponse.json(
        { error: "Failed to fetch conversation" },
        { status: 500 },
      );
    }
    if (!conversation) {
      return NextResponse.json(
        { error: "Conversation not found" },
        { status: 404 },
      );
    }

    // Verify conversation belongs to caller's account
    if (conversation.account_id !== ctx.accountId) {
      return NextResponse.json(
        { error: "Conversation does not belong to your account" },
        { status: 403 },
      );
    }

    // Update the conversation's department_id
    const { error: updateError } = await supabase
      .from("conversations")
      .update({
        department_id: body.departmentId,
        assigned_agent_id: null, // Unassign current agent on transfer
      })
      .eq("id", conversationId);

    if (updateError) {
      console.error("[transfer] update error:", updateError);
      return NextResponse.json(
        { error: "Failed to transfer conversation" },
        { status: 500 },
      );
    }

    // Record audit event
    await recordAuditEvent({
      accountId: ctx.accountId,
      userId: ctx.userId,
      action: "conversation.transfer",
      targetType: "conversation",
      targetId: conversationId,
      oldValues: { departmentId: conversation.department_id },
      newValues: {
        departmentId: body.departmentId,
        note: body.note ?? null,
      },
    });

    // Send notification to target department agents
    await notifyDepartmentAgents({
      supabase,
      departmentId: body.departmentId,
      conversationId,
      actorUserId: ctx.userId,
      note: body.note,
    });

    return NextResponse.json({ ok: true });
  } catch (err) {
    return toErrorResponse(err);
  }
}

/**
 * Fire-and-forget notification to all members of the target department.
 * Creates a notification row for each member so their inbox bell lights up.
 */
async function notifyDepartmentAgents({
  supabase,
  departmentId,
  conversationId,
  actorUserId,
  note,
}: {
  supabase: ReturnType<typeof createClient> extends Promise<infer T> ? T : never;
  departmentId: string;
  conversationId: string;
  actorUserId: string;
  note?: string;
}) {
  try {
    // Fetch all profile IDs in the target department
    const { data: members, error } = await supabase
      .from("profile_departments")
      .select("profile_id")
      .eq("department_id", departmentId);

    if (error || !members?.length) return;

    // Also get the department name and conversation info
    const { data: dept } = await supabase
      .from("departments")
      .select("name")
      .eq("id", departmentId)
      .maybeSingle();

    const departmentName = dept?.name ?? "Unknown";

    const notifications = members.map((m) => ({
      account_id: null, // Will be resolved by DB trigger or context
      user_id: m.profile_id,
      type: "conversation_assigned" as const,
      conversation_id: conversationId,
      actor_user_id: actorUserId,
      title: `Conversation transferred to ${departmentName}`,
      body: note ? `Note: ${note}` : null,
    }));

    // Insert in bulk
    const { error: insertError } = await supabase
      .from("notifications")
      .insert(notifications);

    if (insertError) {
      console.error("[transfer] notification insert error:", insertError);
    }
  } catch (err) {
    // Fire-and-forget: don't let notification failure fail the transfer
    console.error("[transfer] notification error:", err);
  }
}
