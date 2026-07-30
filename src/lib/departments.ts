// ============================================================
// Department data-access layer.
//
// Every function here expects to be called from a server context
// (API route or server component). They use the authenticated SSR
// Supabase client so RLS applies.
//
// The admin-only mutating functions (create, update, archive,
// assign, remove) do NOT re-check the caller's role — they assume
// the calling API route has already guarded with `requireRole`.
// ============================================================

import { createClient } from "@/lib/supabase/server";
import type { Profile } from "@/types";

// ── Types ──────────────────────────────────────────────────

export interface Department {
  id: string;
  account_id: string;
  name: string;
  description: string | null;
  created_at: string;
  archived_at: string | null;
  /** Hydrated by list queries; absent on single-get. */
  member_count?: number;
}

export interface CreateDepartmentInput {
  name: string;
  description?: string;
}

export interface UpdateDepartmentInput {
  name?: string;
  description?: string | null;
}

export interface DepartmentMember {
  profile_id: string;
  department_id: string;
  assigned_at: string;
  profile?: {
    user_id: string;
    full_name: string | null;
    email: string | null;
    avatar_url: string | null;
  };
}

// ── Queries ────────────────────────────────────────────────

/**
 * Fetch a single department by id. Returns `null` when the
 * department doesn't exist or the caller's RLS can't see it.
 */
export async function getDepartment(id: string): Promise<Department | null> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from("departments")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (error) {
    console.error("[departments] getDepartment error:", error);
    return null;
  }
  return data as Department | null;
}

/**
 * List departments visible to the current caller. Admin+ users see
 * all departments in their account; agents see only their assigned
 * ones. Includes member_count.
 */
export async function listDepartments(): Promise<Department[]> {
  const supabase = await createClient();

  const { data, error } = await supabase
    .from("departments")
    .select("*, member_count:profile_departments(count)")
    .order("name", { ascending: true });

  if (error) {
    console.error("[departments] listDepartments error:", error);
    return [];
  }

  return (data ?? []).map(normalizeDepartment);
}

/**
 * Create a new department. Caller must be admin+ (guard in the
 * route handler).
 */
export async function createDepartment(
  data: CreateDepartmentInput,
): Promise<Department> {
  const supabase = await createClient();

  const { data: row, error } = await supabase
    .from("departments")
    .insert({
      name: data.name.trim(),
      description: data.description?.trim() ?? null,
    })
    .select()
    .single();

  if (error) {
    console.error("[departments] createDepartment error:", error);
    throw new Error(error.message);
  }

  return row as Department;
}

/**
 * Update a department. Pass `description: null` to clear it.
 * Caller must be admin+.
 */
export async function updateDepartment(
  id: string,
  data: UpdateDepartmentInput,
): Promise<Department> {
  const supabase = await createClient();

  const patch: Record<string, unknown> = {};
  if (data.name !== undefined) patch.name = data.name.trim();
  if (data.description !== undefined) {
    patch.description = data.description?.trim() ?? null;
  }

  const { data: row, error } = await supabase
    .from("departments")
    .update(patch)
    .eq("id", id)
    .select()
    .single();

  if (error) {
    console.error("[departments] updateDepartment error:", error);
    throw new Error(error.message);
  }

  return row as Department;
}

/**
 * Archive a department (sets `archived_at` to now). Un-archive by
 * calling `updateDepartment` with `archived_at: null` — but that
 * requires extending the input type or using a raw update. For now
 * archive is one-way from the API; un-archive is a DB patch.
 */
export async function archiveDepartment(id: string): Promise<void> {
  const supabase = await createClient();

  const { error } = await supabase
    .from("departments")
    .update({ archived_at: new Date().toISOString() })
    .eq("id", id);

  if (error) {
    console.error("[departments] archiveDepartment error:", error);
    throw new Error(error.message);
  }
}

// ── Membership ─────────────────────────────────────────────

/**
 * Assign a profile to a department. Idempotent — if the
 * assignment already exists, the PK violation is swallowed (the
 * caller gets success). Caller must be admin+.
 */
export async function assignToDepartment(
  profileId: string,
  departmentId: string,
): Promise<void> {
  const supabase = await createClient();

  const { error } = await supabase
    .from("profile_departments")
    .insert({ profile_id: profileId, department_id: departmentId });

  if (error && error.code !== "23505") {
    // 23505 = unique_violation — idempotent, swallow
    console.error("[departments] assignToDepartment error:", error);
    throw new Error(error.message);
  }
}

/**
 * Remove a profile from a department. No-op if the assignment
 * doesn't exist. Caller must be admin+.
 */
export async function removeFromDepartment(
  profileId: string,
  departmentId: string,
): Promise<void> {
  const supabase = await createClient();

  const { error } = await supabase
    .from("profile_departments")
    .delete()
    .eq("profile_id", profileId)
    .eq("department_id", departmentId);

  if (error) {
    console.error("[departments] removeFromDepartment error:", error);
    throw new Error(error.message);
  }
}

/**
 * List members of a department. Caller must be admin+.
 */
export async function getDepartmentMembers(
  departmentId: string,
): Promise<DepartmentMember[]> {
  const supabase = await createClient();

  const { data, error } = await supabase
    .from("profile_departments")
    .select("*, profile:profiles(user_id, full_name, email, avatar_url)")
    .eq("department_id", departmentId)
    .order("assigned_at", { ascending: true });

  if (error) {
    console.error("[departments] getDepartmentMembers error:", error);
    return [];
  }

  return data as DepartmentMember[];
}

// ── Caller's departments ───────────────────────────────────

/**
 * Get the list of department IDs the current user can see (their
 * assigned departments, or all departments for admins).
 */
export async function getMyDepartmentIds(): Promise<string[]> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc("get_user_department_ids");

  if (error) {
    console.error("[departments] getMyDepartmentIds error:", error);
    return [];
  }

  return (data as string[]) ?? [];
}

/**
 * Get full department objects for the current user's departments.
 */
export async function getMyDepartments(): Promise<Department[]> {
  const ids = await getMyDepartmentIds();
  if (ids.length === 0) return [];

  const supabase = await createClient();

  const { data, error } = await supabase
    .from("departments")
    .select("*, member_count:profile_departments(count)")
    .in("id", ids)
    .order("name", { ascending: true });

  if (error) {
    console.error("[departments] getMyDepartments error:", error);
    return [];
  }

  return (data ?? []).map(normalizeDepartment);
}

// ── Internal ───────────────────────────────────────────────

interface RawDepartment {
  id: string;
  account_id: string;
  name: string;
  description: string | null;
  created_at: string;
  archived_at: string | null;
  member_count?: { count: number } | { length?: number } | number | null;
}

function normalizeDepartment(raw: RawDepartment): Department {
  const { member_count, ...rest } = raw;
  let count: number | undefined;

  if (typeof member_count === "number") {
    count = member_count;
  } else if (member_count && typeof member_count === "object") {
    // Supabase aggregate format: { count: 5 } or { length: 5 }
    count =
      ("count" in member_count
        ? (member_count as { count: number }).count
        : (member_count as { length?: number }).length) ?? undefined;
  }

  return { ...rest, member_count: count };
}
