/**
 * Provider registry — resolves the active WhatsAppProvider for a given
 * account by reading `whatsapp_config.provider` and instantiating the
 * correct adapter.
 *
 * Results are cached per-account with a 60-second TTL so repeated sends
 * within a short window don't hammer the database.
 */

import { createClient } from '@supabase/supabase-js';
import type { WhatsAppProvider } from './provider';
import { MetaAdapter } from './meta-adapter';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CachedProvider {
  provider: WhatsAppProvider;
  expiresAt: number;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const cache = new Map<string, CachedProvider>();
const TTL = 60_000; // 60 seconds

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Create a Supabase admin client using the service-role key.
 * This bypasses RLS so the registry can read config for any account.
 */
function supabaseAdmin() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Get the WhatsAppProvider for an account. Cached per account with a 60s TTL.
 *
 * Reads `whatsapp_config.provider` to determine which adapter to use:
 * - `'meta'`   → MetaAdapter (Meta Cloud API)
 * - `'openwa'` → currently returns MetaAdapter as fallback;
 *                 OpenWAAdapter comes in a follow-up PR.
 *
 * Throws if `whatsapp_config` is not found for the given account.
 */
export async function getProvider(accountId: string): Promise<WhatsAppProvider> {
  const cached = cache.get(accountId);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.provider;
  }

  const supabase = supabaseAdmin();
  const { data, error } = await supabase
    .from('whatsapp_config')
    .select('provider, access_token, phone_number_id, waba_id, provider_config')
    .eq('account_id', accountId)
    .single();

  if (error || !data) {
    throw new Error(`WhatsApp config not found for account ${accountId}`);
  }

  // Build the adapter based on the provider field.
  // OpenWA support is stubbed until OpenWAAdapter is implemented in PR #2.
  const provider: WhatsAppProvider = new MetaAdapter({
    accessToken: data.access_token,
    phoneNumberId: data.phone_number_id,
    wabaId: data.waba_id,
  });

  cache.set(accountId, { provider, expiresAt: Date.now() + TTL });
  return provider;
}

/**
 * Clear the provider cache.
 *
 * @param accountId — If provided, clears only the cache entry for that account.
 *                    If omitted, clears the entire cache.
 */
export function clearProviderCache(accountId?: string): void {
  if (accountId) {
    cache.delete(accountId);
  } else {
    cache.clear();
  }
}
