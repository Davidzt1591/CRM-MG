import { NextResponse } from 'next/server'
import { encrypt, decrypt } from '@/lib/whatsapp/encryption'
import { recordAuditEvent } from '@/lib/audit'
import { requireRole, toErrorResponse } from '@/lib/auth/account'

/**
 * GET /api/admin/whatsapp/provider
 *
 * Returns the current provider configuration for the caller's account.
 * Sensitive fields (access_token, api_key, secret) are masked.
 *
 * Access is gated by `requireRole("admin")` (D8) — the same boundary the
 * audit-logs route uses. The caller's account_id and user_id come from the
 * requireRole context instead of a separate getUser()/resolveAccountId()
 * lookup, eliminating a second round-trip and the role-bypass surface it
 * left open (MCRM-58).
 */
export async function GET() {
  try {
    const ctx = await requireRole('admin')
    const accountId = ctx.accountId

    const { data: config, error: dbError } = await ctx.supabase
      .from('whatsapp_config')
      .select('provider, provider_config, phone_number_id, waba_id')
      .eq('account_id', accountId)
      .maybeSingle()

    if (dbError) {
      console.error('[provider-config GET] DB error:', dbError)
      return NextResponse.json({ error: 'Failed to fetch config' }, { status: 500 })
    }

    if (!config) {
      return NextResponse.json({
        provider: 'meta',
        phone_number_id: '',
        waba_id: '',
        api_url: '',
        api_key: '',
        webhook_secret: '',
      })
    }

    const providerConfig = (config.provider_config as Record<string, unknown>) ?? {}

    return NextResponse.json({
      provider: config.provider ?? 'meta',
      phone_number_id: config.phone_number_id ?? '',
      waba_id: config.waba_id ?? '',
      api_url: (providerConfig.apiUrl as string) ?? '',
      api_key: providerConfig.apiKey ? '••••••••••••••••' : '',
      webhook_secret: providerConfig.secret ? '••••••••••••••••' : '',
    })
  } catch (err) {
    return toErrorResponse(err)
  }
}

/**
 * POST /api/admin/whatsapp/provider
 *
 * Saves the provider selection and provider-specific configuration.
 * Sensitive fields are encrypted before storage. Logs an audit event
 * when the provider type changes.
 */
export async function POST(request: Request) {
  try {
    const ctx = await requireRole('admin')
    const accountId = ctx.accountId

    const body = await request.json()
    const { provider, ...rest } = body as {
      provider: string
      phone_number_id?: string
      waba_id?: string
      access_token?: string
      api_url?: string
      api_key?: string
      webhook_secret?: string
    }

    if (provider !== 'meta' && provider !== 'openwa') {
      return NextResponse.json(
        { error: 'provider must be "meta" or "openwa"' },
        { status: 400 },
      )
    }

    // Fetch the existing config so we can detect provider switches.
    const { data: existing } = await ctx.supabase
      .from('whatsapp_config')
      .select('provider')
      .eq('account_id', accountId)
      .maybeSingle()

    const previousProvider = (existing as { provider?: string } | null)?.provider ?? null
    const isSwitch = previousProvider && previousProvider !== provider

    // Build the update payload.
    const updatePayload: Record<string, unknown> = {
      provider,
      updated_at: new Date().toISOString(),
    }

    if (provider === 'meta') {
      // Meta: store phone_number_id, waba_id, and optionally a new access_token.
      if (rest.phone_number_id) {
        updatePayload.phone_number_id = rest.phone_number_id
      }
      if (rest.waba_id) {
        updatePayload.waba_id = rest.waba_id
      }
      if (rest.access_token && rest.access_token !== '••••••••••••••••') {
        try {
          updatePayload.access_token = encrypt(rest.access_token)
        } catch (err) {
          console.error('[provider-config POST] encryption failed:', err)
          return NextResponse.json(
            { error: 'Failed to encrypt access_token. Check ENCRYPTION_KEY.' },
            { status: 500 },
          )
        }
      }
    } else {
      // OpenWA: store api_url, api_key, webhook_secret in provider_config JSONB.
      const providerConfig: Record<string, string> = {}

      if (rest.api_url) {
        providerConfig.apiUrl = rest.api_url.replace(/\/+$/, '')
      }
      if (rest.api_key && rest.api_key !== '••••••••••••••••') {
        try {
          providerConfig.apiKey = encrypt(rest.api_key)
        } catch (err) {
          console.error('[provider-config POST] encryption failed:', err)
          return NextResponse.json(
            { error: 'Failed to encrypt api_key. Check ENCRYPTION_KEY.' },
            { status: 500 },
          )
        }
      }
      if (rest.webhook_secret && rest.webhook_secret !== '••••••••••••••••') {
        try {
          providerConfig.secret = encrypt(rest.webhook_secret)
        } catch (err) {
          console.error('[provider-config POST] encryption failed:', err)
          return NextResponse.json(
            { error: 'Failed to encrypt webhook_secret. Check ENCRYPTION_KEY.' },
            { status: 500 },
          )
        }
      }

      updatePayload.provider_config = providerConfig
    }

    // Upsert the config row.
    if (existing) {
      const { error: updateError } = await ctx.supabase
        .from('whatsapp_config')
        .update(updatePayload)
        .eq('account_id', accountId)

      if (updateError) {
        console.error('[provider-config POST] update error:', updateError)
        return NextResponse.json({ error: 'Failed to save configuration' }, { status: 500 })
      }
    } else {
      // Insert a new row if one doesn't exist (account has no config at all).
      const { error: insertError } = await ctx.supabase
        .from('whatsapp_config')
        .insert({
          account_id: accountId,
          // Attributed to the authenticated caller — sourced from the
          // requireRole context, never a separate getUser() lookup.
          user_id: ctx.userId,
          ...updatePayload,
        })

      if (insertError) {
        console.error('[provider-config POST] insert error:', insertError)
        return NextResponse.json({ error: 'Failed to save configuration' }, { status: 500 })
      }
    }

    // Audit log on provider switch.
    if (isSwitch) {
      await recordAuditEvent({
        accountId,
        userId: ctx.userId,
        action: 'provider.switched',
        targetType: 'whatsapp_config',
        targetId: accountId,
        oldValues: { provider: previousProvider ?? undefined },
        newValues: { provider },
      }).catch((err) =>
        console.error('[provider-config POST] audit log failed:', err),
      )
    }

    return NextResponse.json({ success: true })
  } catch (err) {
    return toErrorResponse(err)
  }
}
