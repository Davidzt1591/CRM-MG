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
-- notifications, with three hard constraints (security review
-- follow-up, cross-account spoofing vector):
--   1. The row belongs to the CALLER's account.
--   2. The RECIPIENT (notifications.user_id, which references
--      auth.users globally) is a member of that same account —
--      a user can never be notified by someone outside their
--      account. profiles.user_id is UNIQUE, so membership is exact.
--   3. The ACTOR (actor_user_id) is pinned to the caller —
--      nobody can spoof who triggered the notification.
-- The SECURITY DEFINER trigger from 027 bypasses RLS entirely, so
-- the system-assignment path is unaffected.
--
-- The route also fixed the payload shape in the same change:
-- account_id is now resolved from the caller's session instead of
-- NULL, and user_id now carries the member's auth.users id (joined
-- from profiles) instead of a profiles.id.

DROP POLICY IF EXISTS notifications_insert ON notifications;
CREATE POLICY notifications_insert ON notifications FOR INSERT
  TO authenticated
  WITH CHECK (
    -- 1) Row stays in the caller's account.
    account_id = (SELECT p.account_id FROM profiles p WHERE p.user_id = auth.uid())
    -- 2) Recipient is a member of that same account. The qualified
    --    `notifications.account_id` is what makes this correlation
    --    safe — an unqualified `account_id = account_id` would bind
    --    to the inner profiles column and be vacuously true.
    AND user_id IN (
      SELECT m.user_id FROM profiles m
      WHERE m.account_id = notifications.account_id
    )
    -- 3) Actor is pinned to the caller; no spoofed actor_user_id.
    AND actor_user_id = auth.uid()
  );
