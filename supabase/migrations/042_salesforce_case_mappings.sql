-- Maps MagnetoCRM conversations to Salesforce cases.
-- Created when an agent escalates a conversation to Salesforce.
-- Also used when a Salesforce-app-originated conversation needs a local mapping.

CREATE TABLE IF NOT EXISTS salesforce_case_mappings (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id            UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  conversation_id       UUID NOT NULL UNIQUE REFERENCES conversations(id) ON DELETE CASCADE,
  salesforce_case_id    TEXT NOT NULL,
  salesforce_case_number TEXT,
  direction             TEXT NOT NULL CHECK (direction IN ('outbound', 'inbound')),
  last_sync_status      TEXT NOT NULL DEFAULT 'pending' CHECK (last_sync_status IN ('pending', 'synced', 'failed')),
  escalation_status     TEXT DEFAULT NULL CHECK (escalation_status IN ('escalated', 'waiting', 'resolved')),
  last_synced_at        TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sf_case_mappings_account ON salesforce_case_mappings(account_id);
CREATE INDEX idx_sf_case_mappings_conversation ON salesforce_case_mappings(conversation_id);

ALTER TABLE salesforce_case_mappings ENABLE ROW LEVEL SECURITY;

-- Admins and owners can do all operations on mappings
CREATE POLICY sf_case_mappings_admin_all
  ON salesforce_case_mappings
  FOR ALL
  USING (is_account_member(account_id, 'admin') OR is_account_member(account_id, 'owner'))
  WITH CHECK (is_account_member(account_id, 'admin') OR is_account_member(account_id, 'owner'));

-- Agents can read mappings (to see escalation status)
CREATE POLICY sf_case_mappings_agent_select
  ON salesforce_case_mappings
  FOR SELECT
  USING (is_account_member(account_id, 'agent'));
