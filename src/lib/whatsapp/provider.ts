/**
 * WhatsAppProvider interface — strategy pattern for WhatsApp messaging.
 *
 * Each supported backend (Meta Cloud API, OpenWA, etc.) implements
 * this interface so the rest of the CRM can send messages, process
 * webhooks, and check provider health without knowing which backend
 * is active for a given account.
 *
 * The strategy is resolved at runtime by `getProvider(accountId)` in
 * provider-registry.ts, which reads `whatsapp_config.provider` and
 * instantiates the correct adapter.
 */

// ---------------------------------------------------------------------------
// Send method argument types
// ---------------------------------------------------------------------------

import type { SendTimeParams } from './template-send-builder';

export interface SendTextArgs {
  to: string
  text: string
  previewUrl?: boolean
  accessToken?: string
  phoneNumberId?: string
}

export interface SendMediaArgs {
  to: string
  mediaType: 'image' | 'video' | 'document' | 'audio'
  mediaUrl: string
  caption?: string
  filename?: string
  accessToken?: string
  phoneNumberId?: string
}

export interface SendTemplateArgs {
  to: string
  templateName: string
  templateLanguage?: string
  /** Legacy positional body params (values for {{1}}, {{2}}, …). */
  templateParams?: string[]
  /** Structured per-send params (header/body/buttons) — see SendTimeParams. */
  templateMessageParams?: SendTimeParams
  accessToken?: string
  phoneNumberId?: string
}

export interface SendInteractiveButtonsArgs {
  to: string
  headerText?: string
  bodyText: string
  footerText?: string
  buttons: Array<{ id: string; title: string }>
  accessToken?: string
  phoneNumberId?: string
}

export interface SendInteractiveListArgs {
  to: string
  headerText?: string
  bodyText: string
  footerText?: string
  buttonText: string
  sections: Array<{
    title?: string
    rows: Array<{ id: string; title: string; description?: string }>
  }>
  accessToken?: string
  phoneNumberId?: string
}

export interface SendReactionArgs {
  to: string
  messageId: string
  emoji: string
  accessToken?: string
  phoneNumberId?: string
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface SendResult {
  messageId: string
  providerMessageId?: string
}

// ---------------------------------------------------------------------------
// Webhook types
// ---------------------------------------------------------------------------

export interface WebhookEvent {
  type: 'message' | 'status' | 'template'
  payload: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Provider status
// ---------------------------------------------------------------------------

export interface ProviderStatus {
  connected: boolean
  label: string
  lastChecked: string
}

// ---------------------------------------------------------------------------
// The interface every provider adapter implements
// ---------------------------------------------------------------------------

export interface WhatsAppProvider {
  /** Human-readable name e.g. "Meta Cloud API", "OpenWA" */
  readonly name: string

  /** Send a text message */
  sendText(args: SendTextArgs): Promise<SendResult>

  /** Send a media message (image, video, document, audio) */
  sendMedia(args: SendMediaArgs): Promise<SendResult>

  /** Send a template message */
  sendTemplate(args: SendTemplateArgs): Promise<SendResult>

  /** Send interactive buttons */
  sendInteractiveButtons(args: SendInteractiveButtonsArgs): Promise<SendResult>

  /** Send interactive list */
  sendInteractiveList(args: SendInteractiveListArgs): Promise<SendResult>

  /** Send a reaction to a message */
  sendReaction(args: SendReactionArgs): Promise<SendResult>

  /** Process an incoming webhook payload */
  processWebhook(payload: unknown): Promise<WebhookEvent[]>

  /** Verify the request signature for webhook security */
  verifyRequest(signature: string, body: string): boolean

  /** Get provider status/health */
  getProviderStatus(): Promise<ProviderStatus>
}
