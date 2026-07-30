"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { createClient } from "@/lib/supabase/client";
import type { Department } from "@/lib/departments";
import type { DepartmentFormValues } from "@/components/admin/department-form";
import { DepartmentList } from "@/components/admin/department-list";
import { toast } from "sonner";

export default function DepartmentsPage() {
  const t = useTranslations("Admin.departments");
  const router = useRouter();
  const [departments, setDepartments] = useState<Department[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchDepartments = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/departments");
      if (!res.ok) throw new Error("Failed to fetch");
      const json = await res.json();
      setDepartments(json.departments ?? []);
    } catch (err) {
      console.error("[departments] fetch error:", err);
      toast.error(t("fetchError"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    fetchDepartments();
  }, [fetchDepartments]);

  const handleCreate = useCallback(
    async (values: DepartmentFormValues) => {
      const res = await fetch("/api/departments", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Failed" }));
        throw new Error(err.error ?? "Failed to create department");
      }
      toast.success(t("created"));
      await fetchDepartments();
    },
    [fetchDepartments, t],
  );

  const handleUpdate = useCallback(
    async (id: string, values: DepartmentFormValues) => {
      const res = await fetch(`/api/departments/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Failed" }));
        throw new Error(err.error ?? "Failed to update department");
      }
      toast.success(t("updated"));
      await fetchDepartments();
    },
    [fetchDepartments, t],
  );

  const handleArchive = useCallback(
    async (id: string) => {
      const res = await fetch(`/api/departments/${id}`, {
        method: "DELETE",
      });
      if (!res.ok) {
        toast.error(t("archiveError"));
        return;
      }
      toast.success(t("archived_success"));
      await fetchDepartments();
    },
    [fetchDepartments, t],
  );

  const handleUnarchive = useCallback(
    async (id: string) => {
      // Un-archive by updating archived_at to null
      const res = await fetch(`/api/departments/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ archived_at: null }),
      });
      if (!res.ok) {
        toast.error(t("unarchiveError"));
        return;
      }
      toast.success(t("unarchived_success"));
      await fetchDepartments();
    },
    [fetchDepartments, t],
  );

  const handleSelect = useCallback(
    (id: string) => {
      router.push(`/admin/departments/${id}`);
    },
    [router],
  );

  return (
    <div className="flex flex-col gap-4 p-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">
          {t("pageTitle")}
        </h1>
        <p className="text-sm text-muted-foreground">{t("pageDesc")}</p>
      </div>

      <DepartmentList
        departments={departments}
        loading={loading}
        onCreate={handleCreate}
        onUpdate={handleUpdate}
        onArchive={handleArchive}
        onUnarchive={handleUnarchive}
        onSelect={handleSelect}
      />
    </div>
  );
}
