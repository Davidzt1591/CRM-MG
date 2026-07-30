-- Add provider column to whatsapp_config for adapter pattern routing
-- Supports 'meta' (Meta Cloud API, default) and 'openwa' (self-hosted OpenWA)

ALTER TABLE whatsapp_config
  ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'meta';

ALTER TABLE whatsapp_config
  ADD CONSTRAINT whatsapp_config_provider_check
    CHECK (provider IN ('meta', 'openwa'));

ALTER TABLE whatsapp_config
  ADD COLUMN IF NOT EXISTS provider_config JSONB DEFAULT '{}'::jsonb;

-- RLS: admins can write provider config
CREATE POLICY "whatsapp_config_admin_write"
  ON whatsapp_config
  FOR ALL
  USING (
    account_id IN (
      SELECT p.account_id FROM profiles p
      WHERE p.user_id = auth.uid()
        AND p.account_role IN ('owner', 'admin')
    )
  );

-- RLS: members can read provider config (send flow needs it)
CREATE POLICY "whatsapp_config_member_read"
  ON whatsapp_config
  FOR SELECT
  USING (
    account_id IN (
      SELECT p.account_id FROM profiles p
      WHERE p.user_id = auth.uid()
    )
  );
