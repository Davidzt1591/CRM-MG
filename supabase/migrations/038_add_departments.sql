-- Migration 038: Departments, profile-department assignments, and helpers
--
-- Slice 2 of the Magneto CRM change set. Introduces:
--   · departments        — named groups agents can belong to
--   · profile_departments— M:N join table
--   · is_member_of_department() — SECURITY DEFINER check
--   · get_user_department_ids() — SECURITY DEFINER helper
--   · RLS policies on all new tables

-- ============================================================
-- TASK-MCRM-14: departments table
-- ============================================================

CREATE TABLE departments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  archived_at TIMESTAMPTZ,
  UNIQUE(account_id, name)
);

ALTER TABLE departments ENABLE ROW LEVEL SECURITY;

-- Members of a department can see it; admins see all
CREATE POLICY "members can view departments" ON departments
  FOR SELECT TO authenticated
  USING (
    is_account_member(account_id)
    AND (
      EXISTS (SELECT 1 FROM profile_departments pd WHERE pd.department_id = id AND pd.profile_id = get_profile_id())
      OR EXISTS (SELECT 1 FROM profiles p WHERE p.id = get_profile_id() AND p.account_role IN ('owner', 'admin'))
    )
  );

CREATE POLICY "admins can manage departments" ON departments
  FOR ALL TO authenticated
  USING (
    is_account_member(account_id)
    AND EXISTS (SELECT 1 FROM profiles p WHERE p.id = get_profile_id() AND p.account_role IN ('owner', 'admin'))
  )
  WITH CHECK (
    is_account_member(account_id)
    AND EXISTS (SELECT 1 FROM profiles p WHERE p.id = get_profile_id() AND p.account_role IN ('owner', 'admin'))
  );

CREATE INDEX idx_departments_account ON departments(account_id);

-- ============================================================
-- TASK-MCRM-15: profile_departments join table
-- ============================================================

CREATE TABLE profile_departments (
  profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  department_id UUID NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (profile_id, department_id)
);

ALTER TABLE profile_departments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "admins can manage profile_departments" ON profile_departments
  FOR ALL TO authenticated
  USING (
    EXISTS (SELECT 1 FROM profiles p WHERE p.id = get_profile_id() AND p.account_role IN ('owner', 'admin'))
  )
  WITH CHECK (
    EXISTS (SELECT 1 FROM profiles p WHERE p.id = get_profile_id() AND p.account_role IN ('owner', 'admin'))
  );

CREATE POLICY "users can view own assignments" ON profile_departments
  FOR SELECT TO authenticated
  USING (profile_id = get_profile_id());

CREATE INDEX idx_profile_departments_profile ON profile_departments(profile_id);
CREATE INDEX idx_profile_departments_department ON profile_departments(department_id);

-- ============================================================
-- TASK-MCRM-16: SECURITY DEFINER functions
-- ============================================================

-- SECURITY DEFINER: bypass RLS to check department membership
CREATE OR REPLACE FUNCTION is_member_of_department(department_id UUID)
RETURNS BOOLEAN
SECURITY DEFINER
AS $$
  SELECT EXISTS (
    SELECT 1 FROM profile_departments pd
    JOIN profiles p ON p.id = pd.profile_id
    WHERE pd.department_id = is_member_of_department.department_id
    AND pd.profile_id = get_profile_id()
    AND (p.account_role IN ('owner', 'admin') OR pd.profile_id = get_profile_id())
  );
$$ LANGUAGE sql;

-- Helper: get departments for current user
CREATE OR REPLACE FUNCTION get_user_department_ids()
RETURNS UUID[]
SECURITY DEFINER
AS $$
  SELECT CASE 
    WHEN p.account_role IN ('owner', 'admin') THEN ARRAY(SELECT d.id FROM departments d WHERE d.account_id = p.account_id)
    ELSE ARRAY(SELECT pd.department_id FROM profile_departments pd WHERE pd.profile_id = get_profile_id())
  END
  FROM profiles p
  WHERE p.id = get_profile_id();
$$ LANGUAGE sql;
