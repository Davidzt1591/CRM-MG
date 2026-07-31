/**
 * Salesforce sync triggers.
 *
 * Server-side functions that bridge MagnetoCRM conversation events to
 * Salesforce Cases:
 *
 * - `escalateToSalesforce`  — Create a Case + mapping, flip conversation to waiting
 * - `syncNoteToSalesforce`  — Append a note as CaseFeed entry
 * - `syncStatusToSalesforce` — Mirror conversation status changes to Salesforce
 *
 * All functions use the service-role admin client to bypass RLS when reading
 * `salesforce_config` (encrypted secrets are only decryptable server-side).
 */

import { createClient } from '@supabase/supabase-js';
import type { SupabaseClient } from '@supabase/supabase-js';
import { SalesforceClient } from './client';
import { recordAuditEvent } from '@/lib/audit';

// ---------------------------------------------------------------------------
// Lazy admin client
// ---------------------------------------------------------------------------

let _adminClient: SupabaseClient | undefined;

function supabaseAdmin() {
  if (!_adminClient) {
    _adminClient = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!,
    );
  }
  return _adminClient;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Load a SalesforceClient for the given account.
 *
 * Reads the encrypted config from `salesforce_config`, decrypts secrets
 * via the `SalesforceClient` constructor, and returns a ready-to-use client.
 *
 * Returns `null` when no config exists for the account (Salesforce not
 * yet configured).
 */
export async function getSalesforceClient(
  accountId: string,
): Promise<SalesforceClient | null> {
  const supabase = supabaseAdmin();
  const { data, error } = await supabase
    .from('salesforce_config')
    .select('*')
    .eq('account_id', accountId)
    .single();

  if (error || !data) return null;
  return new SalesforceClient(data);
}

/**
 * Escalate a conversation to Salesforce.
 *
 * 1. Creates a Case in Salesforce with the provided subject/description
 * 2. Inserts a `salesforce_case_mappings` row linking the conversation
 * 3. Updates the conversation status to `'waiting'`
 * 4. Records an audit event
 *
 * @throws If Salesforce is not configured for the account
 * @returns The Salesforce Case ID and CaseNumber
 */
export async function escalateToSalesforce(
  accountId: string,
  conversationId: string,
  subject: string,
  description?: string,
  contactSalesforceId?: string,
): Promise<{ caseId: string; caseNumber: string }> {
  const client = await getSalesforceClient(accountId);
  if (!client) throw new Error('Salesforce not configured');

  // 1. Create the Case in Salesforce
  const sfCase = await client.createCase({
    subject,
    description,
    contactId: contactSalesforceId,
    origin: 'WhatsApp',
  });

  // 2. Create the local mapping
  const supabase = supabaseAdmin();
  await supabase.from('salesforce_case_mappings').insert({
    account_id: accountId,
    conversation_id: conversationId,
    salesforce_case_id: sfCase.Id,
    salesforce_case_number: sfCase.CaseNumber,
    direction: 'outbound',
    escalation_status: 'escalated',
    last_sync_status: 'synced',
    last_synced_at: new Date().toISOString(),
  });

  // 3. Update conversation status
  await supabase
    .from('conversations')
    .update({ status: 'waiting' })
    .eq('id', conversationId);

  // 4. Audit
  await recordAuditEvent({
    accountId,
    userId: 'system',
    action: 'salesforce.escalated',
    targetType: 'conversation',
    targetId: conversationId,
    newValues: {
      salesforceCaseId: sfCase.Id,
      caseNumber: sfCase.CaseNumber,
    },
  });

  return { caseId: sfCase.Id, caseNumber: sfCase.CaseNumber };
}

/**
 * Sync a note to Salesforce as CaseFeed.
 *
 * Looks up the case mapping for the conversation and posts the note body
 * as a FeedItem. Silently skips conversations that have not been escalated
 * (no mapping exists).
 */
export async function syncNoteToSalesforce(
  accountId: string,
  conversationId: string,
  noteBody: string,
): Promise<void> {
  const supabase = supabaseAdmin();
  const { data: mapping } = await supabase
    .from('salesforce_case_mappings')
    .select('salesforce_case_id')
    .eq('account_id', accountId)
    .eq('conversation_id', conversationId)
    .single();

  if (!mapping) return; // not escalated — nothing to sync

  const client = await getSalesforceClient(accountId);
  if (!client) throw new Error('Salesforce not configured');

  await client.postFeedItem(mapping.salesforce_case_id, noteBody);
}

/**
 * Sync a conversation status change back to Salesforce.
 *
 * Maps MagnetoCRM statuses to Salesforce Case statuses:
 * - `closed`  → `'Closed'`
 * - `waiting` → `'Waiting on Customer'`
 * - any other → `'In Progress'`
 *
 * Silently skips conversations that have no case mapping.
 */
export async function syncStatusToSalesforce(
  accountId: string,
  conversationId: string,
  newStatus: string,
): Promise<void> {
  const supabase = supabaseAdmin();
  const { data: mapping } = await supabase
    .from('salesforce_case_mappings')
    .select('salesforce_case_id')
    .eq('account_id', accountId)
    .eq('conversation_id', conversationId)
    .single();

  if (!mapping) return;

  const client = await getSalesforceClient(accountId);
  if (!client) throw new Error('Salesforce not configured');

  const sfStatus =
    newStatus === 'closed'
      ? 'Closed'
      : newStatus === 'waiting'
        ? 'Waiting on Customer'
        : 'In Progress';

  await client.updateCase(mapping.salesforce_case_id, { Status: sfStatus });
}
