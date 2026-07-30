"use client";

import { useState, useCallback } from "react";
import { useTranslations } from "next-intl";
import type { Department } from "@/lib/departments";
import {
  Dialog,
  DialogPortal,
  DialogOverlay,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Plus,
  Archive,
  Pencil,
  Users,
  Loader2,
  RotateCcw,
} from "lucide-react";
import { DepartmentForm, type DepartmentFormValues } from "./department-form";

interface DepartmentListProps {
  departments: Department[];
  loading: boolean;
  onCreate: (values: DepartmentFormValues) => Promise<void>;
  onUpdate: (id: string, values: DepartmentFormValues) => Promise<void>;
  onArchive: (id: string) => Promise<void>;
  onUnarchive: (id: string) => Promise<void>;
  onSelect: (id: string) => void;
}

export function DepartmentList({
  departments,
  loading,
  onCreate,
  onUpdate,
  onArchive,
  onUnarchive,
  onSelect,
}: DepartmentListProps) {
  const t = useTranslations("Admin.departments");
  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<Department | null>(null);
  const [archivingId, setArchivingId] = useState<string | null>(null);

  const handleCreate = useCallback(
    async (values: DepartmentFormValues) => {
      await onCreate(values);
      setCreateOpen(false);
    },
    [onCreate],
  );

  const handleUpdate = useCallback(
    async (values: DepartmentFormValues) => {
      if (!editTarget) return;
      await onUpdate(editTarget.id, values);
      setEditTarget(null);
    },
    [editTarget, onUpdate],
  );

  const handleArchive = useCallback(
    async (id: string) => {
      setArchivingId(id);
      try {
        await onArchive(id);
      } finally {
        setArchivingId(null);
      }
    },
    [onArchive],
  );

  const handleUnarchive = useCallback(
    async (id: string) => {
      setArchivingId(id);
      try {
        await onUnarchive(id);
      } finally {
        setArchivingId(null);
      }
    },
    [onUnarchive],
  );

  const activeDepartments = departments.filter((d) => !d.archived_at);
  const archivedDepartments = departments.filter((d) => d.archived_at);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header + Create button */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {t("count", { count: activeDepartments.length })}
        </p>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-4 w-4" />
            {t("addDepartment")}
          </Button>
          <DialogPortal>
            <DialogOverlay />
            <DialogContent>
              <DialogTitle>{t("createTitle")}</DialogTitle>
              <DialogDescription>{t("createDescription")}</DialogDescription>
              <DepartmentForm
                onSubmit={handleCreate}
                onCancel={() => setCreateOpen(false)}
                mode="create"
              />
            </DialogContent>
          </DialogPortal>
        </Dialog>
      </div>

      {/* Active departments */}
      {activeDepartments.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
          {t("empty")}
        </div>
      ) : (
        <div className="space-y-2">
          {activeDepartments.map((dept) => (
            <DepartmentCard
              key={dept.id}
              department={dept}
              onEdit={() => setEditTarget(dept)}
              onArchive={() => handleArchive(dept.id)}
              onSelect={() => onSelect(dept.id)}
              isArchiving={archivingId === dept.id}
            />
          ))}
        </div>
      )}

      {/* Archived section */}
      {archivedDepartments.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {t("archived")} ({archivedDepartments.length})
          </h3>
          {archivedDepartments.map((dept) => (
            <DepartmentCard
              key={dept.id}
              department={dept}
              onEdit={() => setEditTarget(dept)}
              onUnarchive={() => handleUnarchive(dept.id)}
              onSelect={() => onSelect(dept.id)}
              isArchiving={archivingId === dept.id}
              archived
            />
          ))}
        </div>
      )}

      {/* Edit dialog */}
      <Dialog
        open={editTarget !== null}
        onOpenChange={(open) => {
          if (!open) setEditTarget(null);
        }}
      >
        {editTarget && (
          <DialogPortal>
            <DialogOverlay />
            <DialogContent>
              <DialogTitle>{t("editTitle")}</DialogTitle>
              <DialogDescription>{t("editDescription")}</DialogDescription>
              <DepartmentForm
                initialValues={{
                  name: editTarget.name,
                  description: editTarget.description ?? "",
                }}
                onSubmit={handleUpdate}
                onCancel={() => setEditTarget(null)}
                mode="edit"
              />
            </DialogContent>
          </DialogPortal>
        )}
      </Dialog>
    </div>
  );
}

// ── Department Card ────────────────────────────────────────

interface DepartmentCardProps {
  department: Department;
  onEdit: () => void;
  onArchive?: () => void | Promise<void>;
  onUnarchive?: () => void | Promise<void>;
  onSelect: () => void;
  isArchiving: boolean;
  archived?: boolean;
}

function DepartmentCard({
  department,
  onEdit,
  onArchive,
  onUnarchive,
  onSelect,
  isArchiving,
  archived,
}: DepartmentCardProps) {
  const t = useTranslations("Admin.departments");

  return (
    <div className="group flex items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3 transition-colors hover:bg-muted/30">
      <button
        type="button"
        onClick={onSelect}
        className="flex flex-1 items-center gap-3 text-left"
      >
        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10 text-sm font-medium text-primary">
          {department.name.charAt(0).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-foreground">
            {department.name}
          </p>
          {department.description && (
            <p className="truncate text-xs text-muted-foreground">
              {department.description}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Users className="h-3.5 w-3.5" />
          <span>{department.member_count ?? 0}</span>
        </div>
      </button>

      <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        <Button
          variant="ghost"
          size="sm"
          className="h-8 w-8 p-0"
          onClick={onEdit}
          title={t("edit")}
        >
          <Pencil className="h-3.5 w-3.5" />
        </Button>

        {archived && onUnarchive ? (
          <Button
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0"
            onClick={onUnarchive}
            disabled={isArchiving}
            title={t("unarchive")}
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </Button>
        ) : onArchive ? (
          <Button
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0 text-muted-foreground hover:text-red-400"
            onClick={onArchive}
            disabled={isArchiving}
            title={t("archive")}
          >
            <Archive className="h-3.5 w-3.5" />
          </Button>
        ) : null}
      </div>
    </div>
  );
}
