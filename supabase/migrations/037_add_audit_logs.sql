CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  action TEXT NOT NULL, -- 'conversation.transfer', 'department.create', 'provider.switch', etc.
  target_type TEXT NOT NULL, -- 'conversation', 'department', 'whatsapp_config', etc.
  target_id UUID,
  old_values JSONB,
  new_values JSONB,
  ip_address INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_account ON audit_logs(account_id, created_at DESC);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Admins can read their account's audit logs
CREATE POLICY "Admins can read audit logs"
  ON audit_logs
  FOR SELECT
  USING (
    account_id IN (
      SELECT p.account_id FROM profiles p
      WHERE p.user_id = auth.uid()
        AND p.account_role IN ('owner', 'admin')
    )
  );

-- The system (service_role) inserts audit logs; individual users
-- never get INSERT/UPDATE/DELETE on this table directly.
