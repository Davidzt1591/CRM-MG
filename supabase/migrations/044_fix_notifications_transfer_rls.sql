-- ============================================================
-- TASK-MCRM-26 / Scenario C: notifications INSERT policy
-- ============================================================
-- The transfer route (POST /api/conversations/[id]/transfer) creates
-- notification rows directly for every member of the target
-- department. Migration 027 anticipated that all notification rows
-- would be created by the SECURITY DEFINER assignment trigger, so it
-- only granted SELECT/UPDATE policies ("rows are created exclusively
-- by the trigger"). Transfers never fire that trigger — they clear
-- assigned_agent_id, which makes the trigger early-return — so the
-- route's client-side inserts were blocked by RLS and the
-- notifications silently vanished.
--
-- Allow any authenticated member of the account to create
-- notifications for their own account. This matches the transfer
-- flow's authorization (any account member can transfer), stays
-- narrower than an open INSERT, and the SECURITY DEFINER trigger
-- keeps working untouched (it bypasses RLS by definition).
--
-- The route also fixed the payload shape in the same change:
-- account_id is now resolved from the caller's session instead of
-- NULL, and user_id now carries the member's auth.users id (joined
-- from profiles) instead of a profiles.id.

DROP POLICY IF EXISTS notifications_insert ON notifications;
CREATE POLICY notifications_insert ON notifications FOR INSERT
  TO authenticated
  WITH CHECK (
    account_id = (SELECT p.account_id FROM profiles p WHERE p.user_id = auth.uid())
  );
