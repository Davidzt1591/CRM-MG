import { createAdminClient } from "@/lib/supabase/admin";

export interface RecordAuditEventParams {
  accountId: string;
  /**
   * User the event is attributed to. OPTIONAL — system-triggered events
   * (Salesforce CDC webhook, escalation sync) pass 'system' or omit the
   * field; recordAuditEvent maps both to NULL so the row satisfies the
   * audit_logs.user_id FK to auth.users (037) after 045 relaxed it to
   * nullable (MCRM-55 / D11).
   */
  userId?: string;
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
 * role changed). Writes go through the SERVICE-ROLE client (SEC-02:
 * append-only via service-role; client RLS read-only) — the admin
 * client lives in a server-only module and must never be imported
 * from a client component. The audit_logs RLS policy remains
 * read-only for clients; nothing here weakens it.
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
  try {
    const supabase = createAdminClient();

    // System events (webhook CDC, escalation sync) have no auth.users
    // FK target. Map the 'system' sentinel — or an omitted userId — to
    // NULL so the insert satisfies the audit_logs.user_id FK (037,
    // relaxed to nullable by 045). Never write the raw 'system' sentinel
    // — it would violate the FK and kill the audit insert.
    const resolvedUserId =
      !params.userId || params.userId === "system" ? null : params.userId;

    const { error } = await supabase.from("audit_logs").insert({
      account_id: params.accountId,
      user_id: resolvedUserId,
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
  } catch (err) {
    // Audit logging must never take down the business operation it
    // trails — a failed insert (RLS, network, schema drift) is logged
    // and swallowed, exactly like the DB error path above.
    console.error("[audit] recordAuditEvent threw:", {
      action: params.action,
      targetType: params.targetType,
      error: err instanceof Error ? err.message : String(err),
    });
  }
}
