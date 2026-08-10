-- Migration 039: Add department_id to conversations and update RLS
--
-- TASK-MCRM-17: Agents see conversations in their departments OR
-- unassigned (department_id IS NULL). Admins see all.

ALTER TABLE conversations ADD COLUMN department_id UUID REFERENCES departments(id) ON DELETE SET NULL;
CREATE INDEX idx_conversations_department ON conversations(department_id);

-- Replace the existing "users can view conversations" policy with one that
-- respects department boundaries. The old policy is dropped first so the
-- migration is idempotent if re-run.
DROP POLICY IF EXISTS "users can view conversations" ON conversations;
CREATE POLICY "users can view conversations" ON conversations
  FOR SELECT TO authenticated
  USING (
    is_account_member(account_id)
    AND (
      EXISTS (SELECT 1 FROM profiles p WHERE p.id = get_profile_id() AND p.account_role IN ('owner', 'admin'))
      OR department_id IS NULL
      OR is_member_of_department(department_id)
    )
  );

-- Agents can only manage conversations in their departments
CREATE POLICY "agents can manage department conversations" ON conversations
  FOR ALL TO authenticated
  USING (
    is_account_member(account_id)
    AND (
      EXISTS (SELECT 1 FROM profiles p WHERE p.id = get_profile_id() AND p.account_role IN ('owner', 'admin'))
      OR department_id IS NULL
      OR is_member_of_department(department_id)
    )
  )
  WITH CHECK (
    is_account_member(account_id)
    AND (
      EXISTS (SELECT 1 FROM profiles p WHERE p.id = get_profile_id() AND p.account_role IN ('owner', 'admin'))
      OR department_id IS NULL
      OR is_member_of_department(department_id)
    )
  );
