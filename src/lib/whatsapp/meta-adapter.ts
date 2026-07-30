/**
 * MetaAdapter — WhatsAppProvider implementation for Meta Cloud API.
 *
 * Wraps the existing low-level meta-api.ts functions into the
 * WhatsAppProvider interface. No legacy call site is changed;
 * the adapter only adds a clean interface on top of the existing
 * functions.
 *
 * @see src/lib/whatsapp/provider.ts — WhatsAppProvider interface
 * @see src/lib/whatsapp/meta-api.ts — underlying Meta HTTP helpers
 */

import * as meta from '@/lib/whatsapp/meta-api';
import { verifyMetaWebhookSignature } from '@/lib/whatsapp/webhook-signature';
import type {
  WhatsAppProvider,
  SendTextArgs,
  SendMediaArgs,
  SendTemplateArgs,
  SendInteractiveButtonsArgs,
  SendInteractiveListArgs,
  SendReactionArgs,
  SendResult,
  WebhookEvent,
  ProviderStatus,
} from './provider';

export interface MetaAdapterConfig {
  accessToken: string;
  phoneNumberId: string;
  wabaId?: string;
}

export class MetaAdapter implements WhatsAppProvider {
  readonly name = 'Meta Cloud API';

  private accessToken: string;
  private phoneNumberId: string;
  private wabaId?: string;

  constructor(config: MetaAdapterConfig) {
    this.accessToken = config.accessToken;
    this.phoneNumberId = config.phoneNumberId;
    this.wabaId = config.wabaId;
  }

  // -----------------------------------------------------------------------
  // Sending
  // -----------------------------------------------------------------------

  async sendText(args: SendTextArgs): Promise<SendResult> {
    const result = await meta.sendTextMessage({
      to: args.to,
      text: args.text,
      previewUrl: args.previewUrl,
      accessToken: args.accessToken ?? this.accessToken,
      phoneNumberId: args.phoneNumberId ?? this.phoneNumberId,
    });
    return { messageId: result.messageId };
  }

  async sendMedia(args: SendMediaArgs): Promise<SendResult> {
    const result = await meta.sendMediaMessage({
      to: args.to,
      kind: args.mediaType,
      link: args.mediaUrl,
      caption: args.caption,
      filename: args.filename,
      accessToken: args.accessToken ?? this.accessToken,
      phoneNumberId: args.phoneNumberId ?? this.phoneNumberId,
    });
    return { messageId: result.messageId };
  }

  async sendTemplate(args: SendTemplateArgs): Promise<SendResult> {
    const result = await meta.sendTemplateMessage({
      to: args.to,
      templateName: args.templateName,
      language: args.templateLanguage ?? 'en_US',
      params: args.templateParams
        ? Object.values(args.templateParams)
        : args.templateMessageParams ?? [],
      messageParams: args.templateMessageParams ?? undefined,
      accessToken: args.accessToken ?? this.accessToken,
      phoneNumberId: args.phoneNumberId ?? this.phoneNumberId,
    });
    return { messageId: result.messageId };
  }

  async sendInteractiveButtons(
    args: SendInteractiveButtonsArgs,
  ): Promise<SendResult> {
    const result = await meta.sendInteractiveButtons({
      to: args.to,
      bodyText: args.bodyText,
      headerText: args.headerText,
      footerText: args.footerText,
      buttons: args.buttons,
      accessToken: args.accessToken ?? this.accessToken,
      phoneNumberId: args.phoneNumberId ?? this.phoneNumberId,
    });
    return { messageId: result.messageId };
  }

  async sendInteractiveList(
    args: SendInteractiveListArgs,
  ): Promise<SendResult> {
    const result = await meta.sendInteractiveList({
      to: args.to,
      bodyText: args.bodyText,
      buttonLabel: args.buttonText,
      headerText: args.headerText,
      footerText: args.footerText,
      sections: args.sections,
      accessToken: args.accessToken ?? this.accessToken,
      phoneNumberId: args.phoneNumberId ?? this.phoneNumberId,
    });
    return { messageId: result.messageId };
  }

  async sendReaction(args: SendReactionArgs): Promise<SendResult> {
    const result = await meta.sendReactionMessage({
      to: args.to,
      targetMessageId: args.messageId,
      emoji: args.emoji,
      accessToken: args.accessToken ?? this.accessToken,
      phoneNumberId: args.phoneNumberId ?? this.phoneNumberId,
    });
    return { messageId: result.messageId };
  }

  // -----------------------------------------------------------------------
  // Webhook handling
  // -----------------------------------------------------------------------

  /**
   * Parse a Meta Cloud API webhook payload into our generic WebhookEvent[].
   *
   * Meta's webhook body has the shape:
   *   { object: "whatsapp_business_account", entry: [{ changes: [{ value, field }] }] }
   *
   * Each top-level change may contain messages[], statuses[], or
   * template_category_update[].
   */
  async processWebhook(payload: unknown): Promise<WebhookEvent[]> {
    const events: WebhookEvent[] = [];
    const body = payload as Record<string, unknown>;

    if (!body?.entry || !Array.isArray(body.entry)) {
      return events;
    }

    for (const entry of body.entry as Array<Record<string, unknown>>) {
      const changes = entry.changes as
        | Array<Record<string, unknown>>
        | undefined;
      if (!changes) continue;

      for (const change of changes) {
        const value = change.value as Record<string, unknown> | undefined;
        if (!value) continue;

        // Incoming messages
        const messages = value.messages as
          | Array<Record<string, unknown>>
          | undefined;
        if (messages) {
          for (const msg of messages) {
            const from = msg.from as string | undefined;
            const msgId = msg.id as string | undefined;
            const msgType = msg.type as string | undefined;
            events.push({
              type: 'message',
              payload: {
                from,
                messageId: msgId,
                messageType: msgType,
                timestamp: msg.timestamp,
                ...(msgType === 'text'
                  ? { text: (msg.text as Record<string, string>)?.body }
                  : {}),
              },
            });
          }
        }

        // Status updates (sent, delivered, read, failed)
        const statuses = value.statuses as
          | Array<Record<string, unknown>>
          | undefined;
        if (statuses) {
          for (const st of statuses) {
            events.push({
              type: 'status',
              payload: {
                messageId: st.id as string,
                status: st.status as string,
                timestamp: st.timestamp as string,
                recipientId: st.recipient_id as string,
              },
            });
          }
        }
      }
    }

    return events;
  }

  verifyRequest(signature: string, body: string): boolean {
    return verifyMetaWebhookSignature(body, signature);
  }

  // -----------------------------------------------------------------------
  // Provider health
  // -----------------------------------------------------------------------

  async getProviderStatus(): Promise<ProviderStatus> {
    try {
      await meta.verifyPhoneNumber({
        phoneNumberId: this.phoneNumberId,
        accessToken: this.accessToken,
      });
      return {
        connected: true,
        label: this.name,
        lastChecked: new Date().toISOString(),
      };
    } catch {
      return {
        connected: false,
        label: this.name,
        lastChecked: new Date().toISOString(),
      };
    }
  }
}
