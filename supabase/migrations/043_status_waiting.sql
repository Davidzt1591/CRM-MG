-- Add 'waiting' to conversation status CHECK constraint.
-- The 'waiting' status indicates a conversation has been escalated to
-- Salesforce and is awaiting a resolution from the external system.
--
-- PostgreSQL auto-generated the constraint name as
-- "conversations_status_check" from the inline CHECK in migration 001.

ALTER TABLE conversations
  DROP CONSTRAINT IF EXISTS conversations_status_check;

ALTER TABLE conversations
  ADD CONSTRAINT conversations_status_check
  CHECK (status IN ('active', 'pending', 'closed', 'waiting'));
