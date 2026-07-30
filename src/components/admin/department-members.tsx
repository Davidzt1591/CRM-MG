"use client";

import { useState, useCallback } from "react";
import { useTranslations } from "next-intl";
import type { DepartmentMember } from "@/lib/departments";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Avatar } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Loader2, UserPlus, X } from "lucide-react";

interface DepartmentMembersProps {
  members: DepartmentMember[];
  /** Available profiles to add (account members not yet in this dept) */
  availableProfiles: Array<{
    user_id: string;
    full_name: string | null;
    email: string | null;
    avatar_url: string | null;
    account_role: string;
  }>;
  loading: boolean;
  onAssign: (profileId: string) => Promise<void>;
  onRemove: (profileId: string) => Promise<void>;
}

export function DepartmentMembers({
  members,
  availableProfiles,
  loading,
  onAssign,
  onRemove,
}: DepartmentMembersProps) {
  const t = useTranslations("Admin.departments");
  const [selectedUserId, setSelectedUserId] = useState<string>("");
  const [assigning, setAssigning] = useState(false);
  const [removingId, setRemovingId] = useState<string | null>(null);

  const handleAssign = useCallback(async () => {
    if (!selectedUserId) return;
    setAssigning(true);
    try {
      await onAssign(selectedUserId);
      setSelectedUserId("");
    } finally {
      setAssigning(false);
    }
  }, [selectedUserId, onAssign]);

  const handleRemove = useCallback(
    async (profileId: string) => {
      setRemovingId(profileId);
      try {
        await onRemove(profileId);
      } finally {
        setRemovingId(null);
      }
    },
    [onRemove],
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Add member */}
      {availableProfiles.length > 0 && (
        <div className="flex items-center gap-2">
          <div className="flex-1">
            <Select value={selectedUserId} onValueChange={(value) => setSelectedUserId(value ?? "")}>
              <SelectTrigger className="border-border bg-muted">
                <SelectValue placeholder={t("selectMemberPlaceholder")} />
              </SelectTrigger>
              <SelectContent>
                {availableProfiles.map((p) => (
                  <SelectItem key={p.user_id} value={p.user_id}>
                    <span className="flex items-center gap-2">
                      <span>{p.full_name ?? p.email}</span>
                      <Badge
                        variant="outline"
                        className="border-border text-[10px]"
                      >
                        {p.account_role}
                      </Badge>
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button
            size="sm"
            onClick={handleAssign}
            disabled={!selectedUserId || assigning}
          >
            {assigning ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <UserPlus className="mr-1 h-4 w-4" />
            )}
            {t("add")}
          </Button>
        </div>
      )}

      {/* Member list */}
      {members.length === 0 ? (
        <p className="py-4 text-center text-sm text-muted-foreground">
          {t("noMembers")}
        </p>
      ) : (
        <div className="space-y-1">
          {members.map((m) => (
            <div
              key={m.profile_id}
              className="flex items-center justify-between gap-3 rounded-lg px-3 py-2 transition-colors hover:bg-muted/30"
            >
              <div className="flex items-center gap-3">
                <Avatar className="h-8 w-8 bg-muted text-xs font-medium text-foreground">
                  {m.profile?.full_name?.charAt(0).toUpperCase() ?? "?"}
                </Avatar>
                <div>
                  <p className="text-sm font-medium text-foreground">
                    {m.profile?.full_name ?? "Unknown"}
                  </p>
                  {m.profile?.email && (
                    <p className="text-xs text-muted-foreground">
                      {m.profile.email}
                    </p>
                  )}
                </div>
              </div>

              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0 text-muted-foreground hover:text-red-400"
                onClick={() => handleRemove(m.profile_id)}
                disabled={removingId === m.profile_id}
              >
                {removingId === m.profile_id ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <X className="h-3.5 w-3.5" />
                )}
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
