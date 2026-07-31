import "server-only";
import { createClient as createSupabaseClient } from "@supabase/supabase-js";
import type { SupabaseClient } from "@supabase/supabase-js";

// ---------------------------------------------------------------------------
// Service-role Supabase client — SERVER ONLY.
//
// Bypasses RLS entirely (the service role is the owner), so this client
// MUST NEVER be imported from a client component or a route that runs in
// the browser. The `server-only` import above makes Next.js fail the
// build if this module ever leaks into a client bundle. The env key
// (SUPABASE_SERVICE_ROLE_KEY, no NEXT_PUBLIC_ prefix) is also never
// exposed to the browser, so `process.env` reads resolve to undefined
// client-side — a second, independent guard.
//
// Intended for append-only system writes (audit_logs) and admin routes
// that need to read/write across the account boundary. Prefer the
// cookie-based SSR client (`@/lib/supabase/server`) for anything that
// must respect RLS.
// ---------------------------------------------------------------------------

let adminClient: SupabaseClient | undefined;

export function createAdminClient(): SupabaseClient {
  if (!adminClient) {
    adminClient = createSupabaseClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!,
    );
  }
  return adminClient;
}
