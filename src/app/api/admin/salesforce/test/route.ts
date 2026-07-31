/**
 * POST /api/admin/salesforce/test — Test the Salesforce connection.
 *
 * Loads the current config for the authenticated user's account, creates a
 * SalesforceClient, and calls testConnection() to verify credentials.
 */

import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { SalesforceClient } from '@/lib/salesforce/client';

// ---------------------------------------------------------------------------
// Lazy admin client
// ---------------------------------------------------------------------------

let _adminClient: ReturnType<typeof createClient> | null = null;

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
// Auth helper
// ---------------------------------------------------------------------------

async function requireAdmin(request: Request): Promise<{
  accountId: string;
  userId: string;
  error?: NextResponse;
}> {
  const supabase = await supabaseAdmin();

  const {
    data: { session },
    error: sessionError,
  } = await (
    await createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!,
      {
        auth: {
          autoRefreshToken: false,
          persistSession: false,
        },
      },
    )
  ).auth.getSession();

  if (sessionError || !session) {
    return {
      accountId: '',
      userId: '',
      error: NextResponse.json({ error: 'Unauthorized' }, { status: 401 }),
    };
  }

  const { data: profile } = await supabase
    .from('profiles')
    .select('account_id, account_role')
    .eq('user_id', session.user.id)
    .single();

  if (
    !profile ||
    (profile.account_role !== 'admin' && profile.account_role !== 'owner')
  ) {
    return {
      accountId: '',
      userId: '',
      error: NextResponse.json({ error: 'Forbidden' }, { status: 403 }),
    };
  }

  return {
    accountId: profile.account_id as string,
    userId: session.user.id,
  };
}

// ---------------------------------------------------------------------------
// POST — Test connection
// ---------------------------------------------------------------------------

export async function POST(request: Request) {
  try {
    const { accountId, error } = await requireAdmin(request);
    if (error) return error;

    const supabase = supabaseAdmin();

    // Load the encrypted config
    const { data: configRow, error: dbError } = await supabase
      .from('salesforce_config')
      .select('*')
      .eq('account_id', accountId)
      .single();

    if (dbError || !configRow) {
      return NextResponse.json(
        { success: false, message: 'Salesforce not configured' },
        { status: 200 },
      );
    }

    // Create a client (will decrypt secrets)
    const client = new SalesforceClient(configRow);

    // Test the connection
    const result = await client.testConnection();

    // Update last_test_at
    await supabase
      .from('salesforce_config')
      .update({ last_test_at: new Date().toISOString() })
      .eq('id', configRow.id);

    return NextResponse.json(result);
  } catch (err) {
    console.error('[admin/salesforce/test] error:', err);
    return NextResponse.json(
      { success: false, message: (err as Error).message },
      { status: 200 },
    );
  }
}
