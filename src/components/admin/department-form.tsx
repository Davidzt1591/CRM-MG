"use client";

import { useState, useCallback } from "react";
import { useTranslations } from "next-intl";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Loader2 } from "lucide-react";

export interface DepartmentFormValues {
  name: string;
  description: string;
}

interface DepartmentFormProps {
  initialValues?: Partial<DepartmentFormValues>;
  onSubmit: (values: DepartmentFormValues) => Promise<void>;
  onCancel: () => void;
  /** "create" (default) or "edit" — drives submit button label */
  mode?: "create" | "edit";
}

export function DepartmentForm({
  initialValues,
  onSubmit,
  onCancel,
  mode = "create",
}: DepartmentFormProps) {
  const t = useTranslations("Admin.departments");
  const [name, setName] = useState(initialValues?.name ?? "");
  const [description, setDescription] = useState(
    initialValues?.description ?? "",
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!name.trim()) return;
      setSubmitting(true);
      setError(null);
      try {
        await onSubmit({ name: name.trim(), description: description.trim() });
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to save");
      } finally {
        setSubmitting(false);
      }
    },
    [name, description, onSubmit],
  );

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="dept-name">{t("nameLabel")}</Label>
        <Input
          id="dept-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={t("namePlaceholder")}
          required
          maxLength={100}
          className="border-border bg-muted"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="dept-desc">{t("descriptionLabel")}</Label>
        <Textarea
          id="dept-desc"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder={t("descriptionPlaceholder")}
          rows={3}
          maxLength={500}
          className="border-border bg-muted"
        />
      </div>

      {error && (
        <p className="text-sm text-red-400">{error}</p>
      )}

      <div className="flex items-center justify-end gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={onCancel}
          disabled={submitting}
        >
          {t("cancel")}
        </Button>
        <Button type="submit" disabled={submitting || !name.trim()}>
          {submitting && <Loader2 className="mr-1 h-4 w-4 animate-spin" />}
          {mode === "create" ? t("create") : t("save")}
        </Button>
      </div>
    </form>
  );
}
