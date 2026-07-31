/**
 * OpenWAAdapter — WhatsAppProvider implementation for OpenWA (wa-automate-nodejs).
 *
 * OpenWA runs as a standalone service (baileys engine) on port 2785 by
 * default. This adapter communicates via REST + Bearer API key auth.
 *
 * @see src/lib/whatsapp/provider.ts — WhatsAppProvider interface
 */

import { randomUUID, createHmac } from 'crypto';
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

export interface OpenWAAdapterConfig {
  apiUrl: string;
  apiKey: string;
  /** Secret used for HMAC-SHA256 webhook signature verification. */
  secret: string;
}

export class OpenWAAdapter implements WhatsAppProvider {
  readonly name = 'OpenWA';

  private apiUrl: string;
  private apiKey: string;
  private secret: string;

  constructor(config: OpenWAAdapterConfig) {
    this.apiUrl = config.apiUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.secret = config.secret;
  }

  // -----------------------------------------------------------------------
  // Sending
  // -----------------------------------------------------------------------

  async sendText(args: SendTextArgs): Promise<SendResult> {
    const res = await fetch(`${this.apiUrl}/send/text`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({
        chatId: args.to.includes('@') ? args.to : `${args.to}@c.us`,
        text: args.text,
      }),
    });
    if (!res.ok) throw new Error(`OpenWA sendText failed: ${res.status}`);
    const data = await res.json().catch(() => ({}));
    return {
      messageId: data.id || randomUUID(),
      providerMessageId: data.id || undefined,
    };
  }

  async sendMedia(args: SendMediaArgs): Promise<SendResult> {
    const res = await fetch(`${this.apiUrl}/send/media`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({
        chatId: args.to.includes('@') ? args.to : `${args.to}@c.us`,
        mediaType: args.mediaType,
        mediaUrl: args.mediaUrl,
        caption: args.caption,
        filename: args.filename,
      }),
    });
    if (!res.ok) throw new Error(`OpenWA sendMedia failed: ${res.status}`);
    const data = await res.json().catch(() => ({}));
    return {
      messageId: data.id || randomUUID(),
      providerMessageId: data.id || undefined,
    };
  }

  async sendTemplate(_args: SendTemplateArgs): Promise<SendResult> {
    throw new Error('OpenWA does not support template messages');
  }

  async sendInteractiveButtons(args: SendInteractiveButtonsArgs): Promise<SendResult> {
    const res = await fetch(`${this.apiUrl}/send/buttons`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({
        chatId: args.to.includes('@') ? args.to : `${args.to}@c.us`,
        bodyText: args.bodyText,
        headerText: args.headerText,
        footerText: args.footerText,
        buttons: args.buttons,
      }),
    });
    if (!res.ok) throw new Error(`OpenWA sendInteractiveButtons failed: ${res.status}`);
    const data = await res.json().catch(() => ({}));
    return {
      messageId: data.id || randomUUID(),
      providerMessageId: data.id || undefined,
    };
  }

  async sendInteractiveList(args: SendInteractiveListArgs): Promise<SendResult> {
    const res = await fetch(`${this.apiUrl}/send/list`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({
        chatId: args.to.includes('@') ? args.to : `${args.to}@c.us`,
        bodyText: args.bodyText,
        headerText: args.headerText,
        footerText: args.footerText,
        buttonText: args.buttonText,
        sections: args.sections,
      }),
    });
    if (!res.ok) throw new Error(`OpenWA sendInteractiveList failed: ${res.status}`);
    const data = await res.json().catch(() => ({}));
    return {
      messageId: data.id || randomUUID(),
      providerMessageId: data.id || undefined,
    };
  }

  async sendReaction(args: SendReactionArgs): Promise<SendResult> {
    const res = await fetch(`${this.apiUrl}/send/reaction`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({
        chatId: args.to.includes('@') ? args.to : `${args.to}@c.us`,
        messageId: args.messageId,
        emoji: args.emoji,
      }),
    });
    if (!res.ok) throw new Error(`OpenWA sendReaction failed: ${res.status}`);
    const data = await res.json().catch(() => ({}));
    return {
      messageId: data.id || randomUUID(),
      providerMessageId: data.id || undefined,
    };
  }

  // -----------------------------------------------------------------------
  // Webhook handling
  // -----------------------------------------------------------------------

  /**
   * Parse an OpenWA webhook payload into our generic WebhookEvent[].
   *
   * OpenWA sends webhooks with the shape:
   *   { event: 'onmessage'|'onack'|..., data: { ... } }
   *
   * - `onmessage` → mapped to a message event
   * - `onack`     → mapped to a status event
   * - Unknown events produce no events (silently ignored).
   */
  async processWebhook(payload: unknown): Promise<WebhookEvent[]> {
    const body = payload as { event?: string; data?: Record<string, unknown> } | null;
    if (!body?.event) return [];

    const events: WebhookEvent[] = [];

    switch (body.event) {
      case 'onmessage': {
        const d = (body.data ?? {}) as Record<string, unknown>;
        events.push({
          type: 'message',
          payload: {
            from: d.from,
            messageId: d.id,
            text: typeof d.body === 'string' ? d.body : undefined,
            timestamp: d.t,
          },
        });
        break;
      }
      case 'onack': {
        const d = (body.data ?? {}) as Record<string, unknown>;
        events.push({
          type: 'status',
          payload: {
            messageId: d.id,
            status: d.status,
            recipientId: d.to,
            timestamp: d.t,
          },
        });
        break;
      }
      // Unknown event types are silently ignored.
    }

    return events;
  }

  verifyRequest(signature: string, body: string): boolean {
    if (!signature) return false;
    const expected = createHmac('sha256', this.secret).update(body).digest('hex');
    // Constant-time comparison to prevent timing attacks.
    const a = Buffer.from(signature);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    try {
      return a.equals(b);
    } catch {
      return false;
    }
  }

  // -----------------------------------------------------------------------
  // Provider health
  // -----------------------------------------------------------------------

  async getProviderStatus(): Promise<ProviderStatus> {
    try {
      const res = await fetch(`${this.apiUrl}/status`, {
        headers: { Authorization: `Bearer ${this.apiKey}` },
      });
      return {
        connected: res.ok,
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

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private headers(): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${this.apiKey}`,
    };
  }
}
