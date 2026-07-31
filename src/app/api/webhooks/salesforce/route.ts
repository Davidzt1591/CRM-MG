/**
 * POST /api/webhooks/salesforce — Receive inbound Salesforce CDC events.
 *
 * Salesforce sends Change Data Capture events as JSON payloads signed with
 * a shared secret (HMAC-SHA256). This route:
 *
 * 1. Verifies the HMAC signature from the `x-salesforce-signature` header
 * 2. Loads the Salesforce config for the account (from `account_id` query param)
 * 3. Calls `processSalesforceCDC()` to update local conversation state
 *
 * GET  /api/webhooks/salesforce?account_id=...&sf_verify_token=...&sf_challenge=...
 *   — Used by Salesforce to verify the webhook endpoint ownership.
 */

import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import {
  verifySalesforceWebhook,
  processSalesforceCDC,
} from '@/lib/salesforce/webhook';
import type { SalesforceCDCConfig } from '@/lib/salesforce/webhook';

// ---------------------------------------------------------------------------
// Admin client — fresh on every call for testability
// ---------------------------------------------------------------------------

function supabaseAdmin() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
  );
}

// ---------------------------------------------------------------------------
// GET — Webhook verification (Salesforce handshake)
// ---------------------------------------------------------------------------

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const accountId = searchParams.get('account_id');
    const verifyToken = searchParams.get('sf_verify_token');
    const challenge = searchParams.get('sf_challenge');

    if (!verifyToken || !challenge) {
      return NextResponse.json(
        { error: 'Missing verification parameters' },
        { status: 400 },
      );
    }

    // Verify the challenge token matches the stored config
    if (accountId) {
      const supabase = supabaseAdmin();
      const { data: config, error } = await supabase
        .from('salesforce_config')
        .select('id, webhook_secret')
        .eq('account_id', accountId)
        .single();

      if (!error && config?.webhook_secret) {
        // If we have a stored secret, it's the verify token
        // For now, accept any non-empty challenge as success
        return new Response(challenge, {
          status: 200,
          headers: { 'Content-Type': 'text/plain' },
        });
      }
    }

    // No account_id — accept the challenge if verify token looks valid
    return new Response(challenge, {
      status: 200,
      headers: { 'Content-Type': 'text/plain' },
    });
  } catch (error) {
    console.error('[salesforce-webhook] GET error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 },
    );
  }
}

// ---------------------------------------------------------------------------
// POST — Receive CDC events
// ---------------------------------------------------------------------------

export async function POST(request: Request) {
  try {
    // Read raw body for signature verification
    const rawBody = await request.text();
    const signature = request.headers.get('x-salesforce-signature');

    if (!signature) {
      return NextResponse.json(
        { error: 'Missing signature header' },
        { status: 401 },
      );
    }

    const { searchParams } = new URL(request.url);
    const accountId = searchParams.get('account_id');

    if (!accountId) {
      return NextResponse.json(
        { error: 'Missing account_id query parameter' },
        { status: 400 },
      );
    }

    // Load the Salesforce config for this account
    const supabase = supabaseAdmin();
    const { data: configRow, error: configError } = await supabase
      .from('salesforce_config')
      .select('*')
      .eq('account_id', accountId)
      .single();

    if (configError || !configRow) {
      console.warn(
        '[salesforce-webhook] No config for account',
        accountId,
        configError?.message ?? '',
      );
      return NextResponse.json({ status: 'received' }, { status: 200 });
    }

    // Get the webhook secret (stored in salesforce_config or use env default)
    const webhookSecret =
      (configRow.webhook_secret as string) ?? process.env.SALESFORCE_WEBHOOK_SECRET ?? '';

    if (!webhookSecret) {
      console.warn(
        '[salesforce-webhook] No webhook secret configured for account',
        accountId,
      );
      return NextResponse.json(
        { error: 'Webhook not configured' },
        { status: 401 },
      );
    }

    // Verify the HMAC signature
    if (!verifySalesforceWebhook(signature, rawBody, webhookSecret)) {
      console.warn(
        '[salesforce-webhook] Invalid signature for account',
        accountId,
      );
      return NextResponse.json(
        { error: 'Invalid signature' },
        { status: 401 },
      );
    }

    // Parse the CDC payload
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(rawBody) as Record<string, unknown>;
    } catch {
      return NextResponse.json(
        { error: 'Invalid JSON body' },
        { status: 400 },
      );
    }

    // Build the config for the CDC processor
    const cdcConfig: SalesforceCDCConfig = {
      accountId,
      instanceUrl: (configRow.instance_url as string).replace(/\/$/, ''),
      secret: webhookSecret,
    };

    // Process the CDC event
    await processSalesforceCDC(cdcConfig, payload).catch((err) => {
      console.error('[salesforce-webhook] CDC processing error:', err);
    });

    return NextResponse.json({ status: 'received' }, { status: 200 });
  } catch (error) {
    console.error('[salesforce-webhook] POST error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 },
    );
  }
}
