"use client";

import { useState, useEffect, useCallback } from "react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";
import { Loader2 } from "lucide-react";

// MCRM-24: read-only audit trail viewer. Data comes from
// /api/admin/audit-logs (owner/admin only, scoped to the account by
// the route and by the 037 RLS policy). No mutations exist here on
// purpose — audit rows are append-only.

export interface AuditLogEntry {
  id: string;
  user_id: string;
  action: string;
  target_type: string;
  target_id: string | null;
  old_values: Record<string, unknown> | null;
  new_values: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
}

function shortId(id: string | null | undefined): string {
  if (!id) return "—";
  return id.length > 8 ? `${id.slice(0, 8)}…` : id;
}

function formatChanges(entry: AuditLogEntry): string {
  const parts: string[] = [];
  if (entry.old_values) parts.push(`- ${JSON.stringify(entry.old_values)}`);
  if (entry.new_values) parts.push(`+ ${JSON.stringify(entry.new_values)}`);
  return parts.join(" ");
}

export default function AuditLogsPage() {
  const t = useTranslations("Admin.auditLogs");
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/admin/audit-logs");
      if (!res.ok) throw new Error("Failed to fetch");
      const json = await res.json();
      setLogs(json.logs ?? []);
    } catch (err) {
      console.error("[audit-logs] fetch error:", err);
      toast.error(t("fetchError"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  return (
    <div className="flex flex-col gap-4 p-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">{t("pageTitle")}</h1>
        <p className="text-sm text-muted-foreground">{t("pageDesc")}</p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="size-6 animate-spin text-muted-foreground" />
        </div>
      ) : logs.length === 0 ? (
        <p className="py-16 text-center text-sm text-muted-foreground">
          {t("empty")}
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-left text-sm">
            <thead className="border-b bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-4 py-3 font-medium">{t("columns.date")}</th>
                <th className="px-4 py-3 font-medium">{t("columns.action")}</th>
                <th className="px-4 py-3 font-medium">{t("columns.user")}</th>
                <th className="px-4 py-3 font-medium">{t("columns.targetType")}</th>
                <th className="px-4 py-3 font-medium">{t("columns.targetId")}</th>
                <th className="px-4 py-3 font-medium">{t("columns.changes")}</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {logs.map((entry) => {
                const changes = formatChanges(entry);
                return (
                  <tr key={entry.id} className="align-top hover:bg-muted/30">
                    <td className="whitespace-nowrap px-4 py-3 text-muted-foreground">
                      {new Date(entry.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">{entry.action}</td>
                    <td className="px-4 py-3 font-mono text-xs" title={entry.user_id}>
                      {shortId(entry.user_id)}
                    </td>
                    <td className="px-4 py-3">{entry.target_type}</td>
                    <td className="px-4 py-3 font-mono text-xs" title={entry.target_id ?? ""}>
                      {shortId(entry.target_id)}
                    </td>
                    <td className="max-w-md truncate px-4 py-3 font-mono text-xs text-muted-foreground">
                      {changes || t("noChanges")}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
