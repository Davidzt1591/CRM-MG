-- Salesforce integration configuration per account.
-- Secrets (client_id, client_secret, username, password, security_token)
-- are encrypted via app-level AES-256-GCM before storage.

CREATE TABLE IF NOT EXISTS salesforce_config (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id    UUID NOT NULL UNIQUE REFERENCES accounts(id) ON DELETE CASCADE,
  instance_url  TEXT NOT NULL,
  is_sandbox    BOOLEAN NOT NULL DEFAULT TRUE,
  client_id     TEXT NOT NULL,        -- encrypted
  client_secret TEXT NOT NULL,        -- encrypted
  username      TEXT NOT NULL,        -- encrypted
  password      TEXT NOT NULL,        -- encrypted
  security_token TEXT,                -- encrypted, nullable
  connected_at  TIMESTAMPTZ,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE salesforce_config ENABLE ROW LEVEL SECURITY;

-- Admins and owners can write (INSERT/UPDATE/DELETE) Salesforce config
CREATE POLICY salesforce_config_admin_write
  ON salesforce_config
  FOR ALL
  USING (
    is_account_member(account_id, 'admin') OR
    is_account_member(account_id, 'owner')
  )
  WITH CHECK (
    is_account_member(account_id, 'admin') OR
    is_account_member(account_id, 'owner')
  );

-- Admins and owners can read Salesforce config
CREATE POLICY salesforce_config_admin_read
  ON salesforce_config
  FOR SELECT
  USING (
    is_account_member(account_id, 'admin') OR
    is_account_member(account_id, 'owner')
  );
