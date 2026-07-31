"use client";

import { useState, useEffect, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { createClient } from "@/lib/supabase/client";
import type { Department, DepartmentMember } from "@/lib/departments";
import { DepartmentMembers } from "@/components/admin/department-members";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Loader2 } from "lucide-react";
import { toast } from "sonner";

export default function DepartmentDetailPage() {
  const t = useTranslations("Admin.departments");
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const [department, setDepartment] = useState<Department | null>(null);
  const [members, setMembers] = useState<DepartmentMember[]>([]);
  const [availableProfiles, setAvailableProfiles] = useState<
    Array<{
      user_id: string;
      full_name: string | null;
      email: string | null;
      avatar_url: string | null;
      account_role: string;
    }>
  >([]);
  const [loadingDept, setLoadingDept] = useState(true);
  const [loadingMembers, setLoadingMembers] = useState(true);

  const fetchDepartment = useCallback(async () => {
    setLoadingDept(true);
    try {
      const res = await fetch(`/api/departments/${id}`);
      if (!res.ok) throw new Error("Not found");
      const json = await res.json();
      setDepartment(json.department);
    } catch {
      toast.error(t("fetchError"));
    } finally {
      setLoadingDept(false);
    }
  }, [id, t]);

  const fetchMembers = useCallback(async () => {
    setLoadingMembers(true);
    try {
      const [membersRes, profilesRes] = await Promise.all([
        fetch(`/api/departments/${id}/members`),
        fetch("/api/account/members"),
      ]);

      if (!membersRes.ok) throw new Error("Failed to fetch members");
      const membersJson = await membersRes.json();
      setMembers(membersJson.members ?? []);

      if (profilesRes.ok) {
        const profilesJson = await profilesRes.json();
        const memberIds = new Set(
          (membersJson.members ?? []).map(
            (m: DepartmentMember) => m.profile_id,
          ),
        );
        const available = (profilesJson.members ?? []).filter(
          (p: { user_id: string }) => !memberIds.has(p.user_id),
        );
        setAvailableProfiles(available);
      }
    } catch {
      toast.error(t("fetchMembersError"));
    } finally {
      setLoadingMembers(false);
    }
  }, [id, t]);

  useEffect(() => {
    fetchDepartment();
    fetchMembers();
  }, [fetchDepartment, fetchMembers]);

  const handleAssign = useCallback(
    async (profileId: string) => {
      const res = await fetch(`/api/departments/${id}/members`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profileId }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Failed" }));
        throw new Error(err.error ?? "Failed to assign member");
      }
      toast.success(t("assigned"));
      await fetchMembers();
    },
    [id, fetchMembers, t],
  );

  const handleRemove = useCallback(
    async (profileId: string) => {
      const res = await fetch(
        `/api/departments/${id}/members?profileId=${profileId}`,
        { method: "DELETE" },
      );
      if (!res.ok) {
        toast.error(t("removeError"));
        return;
      }
      toast.success(t("removed"));
      await fetchMembers();
    },
    [id, fetchMembers, t],
  );

  if (loadingDept) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!department) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-12">
        <p className="text-sm text-muted-foreground">{t("notFound")}</p>
        <Button variant="outline" onClick={() => router.push("/admin/departments")}>
          <ArrowLeft className="mr-1 h-4 w-4" />
          {t("back")}
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="sm"
          className="h-8 w-8 p-0"
          onClick={() => router.push("/admin/departments")}
        >
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-foreground">
              {department.name}
            </h1>
            {department.archived_at && (
              <Badge variant="outline" className="border-border text-[10px]">
                {t("archived")}
              </Badge>
            )}
          </div>
          {department.description && (
            <p className="text-sm text-muted-foreground">
              {department.description}
            </p>
          )}
        </div>
      </div>

      {/* Members section */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-foreground">
          {t("members")} ({members.length})
        </h2>
        <div className="rounded-lg border border-border bg-card p-4">
          <DepartmentMembers
            members={members}
            availableProfiles={availableProfiles}
            loading={loadingMembers}
            onAssign={handleAssign}
            onRemove={handleRemove}
          />
        </div>
      </div>

      {/* Transfer log placeholder — future enhancement */}
      <div className="rounded-lg border border-border bg-card p-4">
        <h2 className="mb-2 text-sm font-semibold text-foreground">
          {t("transferLog")}
        </h2>
        <p className="text-sm text-muted-foreground">
          {t("transferLogEmpty")}
        </p>
      </div>
    </div>
  );
}
