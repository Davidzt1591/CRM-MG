/**
 * Salesforce webhook receiver — inbound CDC (Change Data Capture) handler.
 *
 * Salesforce sends CDC events as JSON payloads signed with a shared secret
 * (HMAC-SHA256, base64-encoded). This module verifies the signature and
 * processes status changes on escalated Cases, updating local conversation
 * state and escalation tracking.
 *
 * @example
 * ```ts
 * import { verifySalesforceWebhook, processSalesforceCDC } from '@/lib/salesforce/webhook'
 *
 * const isValid = verifySalesforceWebhook(signature, rawBody, config.secret)
 * if (!isValid) throw new Error('Invalid signature')
 * await processSalesforceCDC(config, cdcPayload)
 * ```
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { recordAuditEvent } from '@/lib/audit';

// ---------------------------------------------------------------------------
// Lazy admin client — NOT cached between calls so tests can reset cleanly.
// Each call creates a fresh client (acceptable for low-frequency webhook use).
// --------------------------------------------------------------------------- 

function supabaseAdmin() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
  );
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/**
 * Verify an HMAC-SHA256 signature using constant-time comparison.
 *
 * @param signature - The base64-encoded signature from the `x-salesforce-signature` header
 * @param body      - The raw request body that was signed
 * @param secret    - The shared webhook secret
 * @returns `true` when the signature matches, `false` otherwise
 */
export function verifySalesforceWebhook(
  signature: string,
  body: string,
  secret: string,
): boolean {
  if (!signature || !secret) return false;

  const expected = createHmac('sha256', secret).update(body).digest('base64');

  try {
    const sigBuf = Buffer.from(signature);
    const expectedBuf = Buffer.from(expected);

    if (sigBuf.length !== expectedBuf.length) return false;
    return timingSafeEqual(sigBuf, expectedBuf);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SalesforceCDCConfig {
  accountId: string;
  instanceUrl: string;
  secret: string;
}

/**
 * Maps Salesforce Case status values to our internal escalation status.
 */
function mapEscalationStatus(sfStatus: string): string {
  const upper = sfStatus.toUpperCase();
  if (upper.includes('CLOSED')) return 'resolved';
  if (
    upper.includes('WAITING') ||
    upper.includes('HOLD') ||
    upper.includes('ESCALATED')
  ) {
    return 'waiting';
  }
  return 'active';
}

/**
 * Maps Salesforce Case status values to our internal conversation status.
 */
function mapConversationStatus(sfStatus: string): string {
  const upper = sfStatus.toUpperCase();
  if (upper.includes('CLOSED')) return 'closed';
  if (
    upper.includes('WAITING') ||
    upper.includes('HOLD') ||
    upper.includes('ESCALATED')
  ) {
    return 'waiting';
  }
  return 'active';
}

// ---------------------------------------------------------------------------
// CDC processing
// ---------------------------------------------------------------------------

/**
 * Process an inbound Salesforce CDC (Change Data Capture) event.
 *
 * 1. Parses the CDC payload for the Case Id and changed fields
 * 2. Looks up the local `salesforce_case_mappings` row
 * 3. Updates `escalation_status` and `conversation.status` based on the
 *    Salesforce Case's new Status value
 * 4. Inserts a system message into the conversation
 * 5. Records an audit event
 *
 * Skips gracefully when no local mapping exists for the Salesforce Case ID.
 */
export async function processSalesforceCDC(
  config: SalesforceCDCConfig,
  payload: Record<string, unknown>,
): Promise<void> {
  // Only process CDC events with a ChangeEventHeader
  const header = payload.ChangeEventHeader as
    | Record<string, unknown>
    | undefined;
  if (!header) return;

  const recordIds = header.recordIds as string[] | undefined;
  if (!recordIds || recordIds.length === 0) return;

  const salesforceCaseId = recordIds[0];
  const changedFields = (header.changedFields as string[]) ?? [];
  const isStatusChange = changedFields.some((f: string) =>
    f.toLowerCase().includes('status'),
  );

  const supabase = supabaseAdmin();

  // Look up the local mapping
  const { data: mapping, error: mappingError } = await supabase
    .from('salesforce_case_mappings')
    .select('*')
    .eq('salesforce_case_id', salesforceCaseId)
    .single();

  if (mappingError || !mapping) return; // No mapping — not escalated from CRM

  // Extract the new Status value from the CDC payload.
  // CDC events may send Status__c (with __c suffix for custom fields)
  // or Status (standard field).
  const newStatus =
    (payload.Status as string) ??
    (payload.Status__c as string) ??
    null;

  if (newStatus && isStatusChange) {
    const escalationStatus = mapEscalationStatus(newStatus);
    const conversationStatus = mapConversationStatus(newStatus);

    // Update the mapping's escalation_status
    await supabase
      .from('salesforce_case_mappings')
      .update({
        escalation_status: escalationStatus,
        last_sync_status: 'synced',
        updated_at: new Date().toISOString(),
      })
      .eq('id', mapping.id);

    // Update the conversation status
    const conversationId = mapping.conversation_id as string;
    await supabase
      .from('conversations')
      .update({
        status: conversationStatus,
        updated_at: new Date().toISOString(),
      })
      .eq('id', conversationId);

    // Add a system message about the status change
    await supabase.from('messages').insert({
      conversation_id: conversationId,
      sender_type: 'system',
      content_type: 'text',
      content_text: `Case actualizado desde Salesforce: "${newStatus}"`,
      created_at: new Date().toISOString(),
    });
  } else {
    // Non-status change — just mark synced
    await supabase
      .from('salesforce_case_mappings')
      .update({
        last_sync_status: 'synced',
        updated_at: new Date().toISOString(),
      })
      .eq('id', mapping.id);
  }

  // Record audit event
  await recordAuditEvent({
    accountId: config.accountId,
    userId: 'system',
    action: 'salesforce.cdc_received',
    targetType: 'salesforce_case_mapping',
    targetId: mapping.id,
    newValues: {
      salesforceCaseId,
      newStatus,
      changeType: header.changeType as string,
    },
  });
}

/**
 * Process an explicit Salesforce Case update (used by the webhook route
 * when the payload is a simpler Salesforce → Webhook format rather than
 * a full CDC event).
 *
 * Finds the local mapping by `salesforceCaseId` and applies the changes
 * to the conversation.
 */
export async function processSalesforceCaseUpdate(
  config: SalesforceCDCConfig,
  salesforceCaseId: string,
  changes: Record<string, unknown>,
): Promise<void> {
  const supabase = supabaseAdmin();

  // Look up the local mapping
  const { data: mapping, error: mappingError } = await supabase
    .from('salesforce_case_mappings')
    .select('*')
    .eq('salesforce_case_id', salesforceCaseId)
    .single();

  if (mappingError || !mapping) return;

  const newStatus = (changes.Status as string) ?? null;
  if (newStatus) {
    const escalationStatus = mapEscalationStatus(newStatus);
    const conversationStatus = mapConversationStatus(newStatus);
    const conversationId = mapping.conversation_id as string;

    // Update mapping
    await supabase
      .from('salesforce_case_mappings')
      .update({
        escalation_status: escalationStatus,
        last_sync_status: 'synced',
        updated_at: new Date().toISOString(),
      })
      .eq('id', mapping.id);

    // Update conversation
    await supabase
      .from('conversations')
      .update({
        status: conversationStatus,
        updated_at: new Date().toISOString(),
      })
      .eq('id', conversationId);

    // Add system message
    await supabase.from('messages').insert({
      conversation_id: conversationId,
      sender_type: 'system',
      content_type: 'text',
      content_text: `Caso Salesforce actualizado: "${newStatus}"`,
      created_at: new Date().toISOString(),
    });

    // Audit
    await recordAuditEvent({
      accountId: config.accountId,
      userId: 'system',
      action: 'salesforce.case_updated',
      targetType: 'salesforce_case_mapping',
      targetId: mapping.id,
      newValues: { salesforceCaseId, changes },
    });
  }
}
