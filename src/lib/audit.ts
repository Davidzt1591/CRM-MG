import { createClient } from "@/lib/supabase/server";

export interface RecordAuditEventParams {
  accountId: string;
  userId: string;
  action: string;
  targetType: string;
  targetId?: string;
  oldValues?: Record<string, unknown>;
  newValues?: Record<string, unknown>;
  ipAddress?: string;
}

/**
 * Record an audit event in the audit_logs table.
 *
 * Call this from API routes and server actions after a privileged
 * operation (e.g. department created, provider switched, member
 * role changed). Only service_role can write to audit_logs; the
 * function uses the server client which respects RLS.
 *
 * @example
 * ```ts
 * import { recordAuditEvent } from "@/lib/audit";
 *
 * await recordAuditEvent({
 *   accountId: session.accountId,
 *   userId: session.userId,
 *   action: "department.create",
 *   targetType: "department",
 *   targetId: newDept.id,
 *   newValues: { name: "Support", sla_hours: 4 },
 * });
 * ```
 */
export async function recordAuditEvent(
  params: RecordAuditEventParams,
): Promise<void> {
  const supabase = await createClient();

  const { error } = await supabase.from("audit_logs").insert({
    account_id: params.accountId,
    user_id: params.userId,
    action: params.action,
    target_type: params.targetType,
    target_id: params.targetId ?? null,
    old_values: params.oldValues ?? null,
    new_values: params.newValues ?? null,
    ip_address: params.ipAddress ?? null,
  });

  if (error) {
    console.error("[audit] Failed to record event:", {
      action: params.action,
      targetType: params.targetType,
      error: error.message,
    });
  }
}
