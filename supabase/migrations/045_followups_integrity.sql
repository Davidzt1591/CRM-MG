-- ============================================================
-- TASK-MCRM-52..56 / Integrity hotfix (followups slice 1)
-- ============================================================
-- Reconciliation of conversations.status / audit_logs.user_id /
-- salesforce_config.webhook_secret against the codebase.
--
-- Context:
--   * 001 declared status CHECK ('open','pending','closed') with
--     DEFAULT 'open' — the app's resolve-conversation path inserts
--     conversations WITHOUT status, relying on that default.
--   * 043 replaced the CHECK with ('active','pending','closed',
--     'waiting') — 'open' became ILLEGAL, so the omitted-status
--     insert path started failing on any DB with 043 applied.
--   * 042 forbids escalation_status 'active' (CHECK: 'escalated',
--     'waiting','resolved'), but webhook.ts mapEscalationStatus
--     returned 'active' for unrecognized Salesforce statuses —
--     another live CHECK violation.
--   * 037 made audit_logs.user_id NOT NULL FK -> auth.users; webhook
--     and sync paths wrote the sentinel 'system' which has no FK
--     target (and violates the FK when the insert is not caught).
--   * route.ts reads/writes salesforce_config.webhook_secret but no
--     migration ever created the column (drift repair, D3).
--
-- UP is ADDITIVE ONLY: a superset CHECK never rejects existing rows,
-- so no row migration is needed (D1). DEFAULT stays 'open' (001) —
-- omitted-status inserts resolve 'open', now legal again.
--
-- ⛔ PRE-APPLY HARD GATE: verify the deployed Supabase state BEFORE
-- applying this migration (043 applied? conversations with
-- status='open'? webhook inserts currently failing?). This file is
-- safe in either case (superset), but the verification must be
-- documented in the apply report.
--
-- Verification attempt at apply time (SLICE-1 / FK-01):
--   * No supabase/config.toml or supabase/.temp in the repo.
--   * No .env.local present (gitignored); .env.local.example uses
--     the placeholder https://your-project.supabase.co — no real URL.
--   * Cannot confirm whether 043 is applied on the live DB or count
--     existing 'open' rows.
--
-- ✅ UNVERIFIED — must confirm against prod DB before applying.
-- The migration is safe regardless (superset CHECK), but the
-- pre-apply checklist should be run against the deployed Supabase
-- before this file is applied to production.

-- UP
ALTER TABLE conversations
  DROP CONSTRAINT IF EXISTS conversations_status_check;

-- Superset of 001 ('open','pending','closed') ∪ 043
-- ('active','pending','closed','waiting'). 'open' is legal again;
-- DEFAULT stays 'open' (001:144) — omitted-status inserts resolve
-- 'open' and pass the CHECK (MCRM-52).
ALTER TABLE conversations
  ADD CONSTRAINT conversations_status_check
  CHECK (status IN ('open','active','pending','closed','waiting'));

-- System audit events (webhook.ts:209,282 / sync.ts:114) have no
-- auth.users FK target; recordAuditEvent now maps the 'system'
-- sentinel to NULL. Relax the column so those inserts succeed
-- (MCRM-55 / D11).
ALTER TABLE audit_logs
  ALTER COLUMN user_id DROP NOT NULL;

-- Drift repair: the Salesforce config route reads/writes
-- webhook_secret but no migration defined it. Additive, nullable.
ALTER TABLE salesforce_config
  ADD COLUMN IF NOT EXISTS webhook_secret TEXT;

-- DOWN
ALTER TABLE conversations
  DROP CONSTRAINT IF EXISTS conversations_status_check;

-- 043 cannot hold 'open', so reconcile the rows the restored
-- constraint would reject BEFORE re-adding it (D2). 'pending' is the
-- closest 043-legal semantic for an unanswered conversation.
UPDATE conversations SET status = 'pending' WHERE status = 'open';

ALTER TABLE conversations
  ADD CONSTRAINT conversations_status_check
  CHECK (status IN ('active','pending','closed','waiting'));

-- ⚠️ LOSSY BY DESIGN (D4): system audit rows (user_id IS NULL) have
-- no auth.users FK target. On down, 037's NOT NULL constraint must
-- come back, and fabricated attribution to a real user would be
-- worse for a forensic table than dropping the non-attributable
-- system rows. Delete them, loudly, then re-lock the column.
DELETE FROM audit_logs WHERE user_id IS NULL;

ALTER TABLE audit_logs
  ALTER COLUMN user_id SET NOT NULL;

-- Drift repair reversal: 045 added this column (D3). Safe to drop on
-- rollback — the column is nullable and was only created by migration 045.
ALTER TABLE salesforce_config
  DROP COLUMN IF EXISTS webhook_secret;
