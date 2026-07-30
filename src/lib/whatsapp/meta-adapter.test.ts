import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MetaAdapter } from './meta-adapter';

// Mock every meta-api function the adapter delegates to.
const mockSendTextMessage = vi.fn();
const mockSendMediaMessage = vi.fn();
const mockSendTemplateMessage = vi.fn();
const mockSendInteractiveButtons = vi.fn();
const mockSendInteractiveList = vi.fn();
const mockSendReactionMessage = vi.fn();
const mockGetMediaUrl = vi.fn();
const mockDownloadMedia = vi.fn();
const mockVerifyPhoneNumber = vi.fn();

vi.mock('@/lib/whatsapp/meta-api', () => ({
  sendTextMessage: (...args: unknown[]) => mockSendTextMessage(...args),
  sendMediaMessage: (...args: unknown[]) => mockSendMediaMessage(...args),
  sendTemplateMessage: (...args: unknown[]) => mockSendTemplateMessage(...args),
  sendInteractiveButtons: (...args: unknown[]) => mockSendInteractiveButtons(...args),
  sendInteractiveList: (...args: unknown[]) => mockSendInteractiveList(...args),
  sendReactionMessage: (...args: unknown[]) => mockSendReactionMessage(...args),
  getMediaUrl: (...args: unknown[]) => mockGetMediaUrl(...args),
  downloadMedia: (...args: unknown[]) => mockDownloadMedia(...args),
  verifyPhoneNumber: (...args: unknown[]) => mockVerifyPhoneNumber(...args),
}));

// Mock webhook-signature module
vi.mock('@/lib/whatsapp/webhook-signature', () => ({
  verifyMetaWebhookSignature: (body: string, signature: string | null) =>
    signature === 'sha256=valid-hmac',
}));

const BASE_CONFIG = {
  accessToken: 'test-access-token',
  phoneNumberId: 'test-phone-id',
  wabaId: 'test-waba-id',
};

describe('MetaAdapter', () => {
  let adapter: MetaAdapter;

  beforeEach(() => {
    vi.clearAllMocks();
    adapter = new MetaAdapter(BASE_CONFIG);
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  // ── Constructor ──────────────────────────────────────────────

  it('stores config and exposes name', () => {
    expect(adapter.name).toBe('Meta Cloud API');
  });

  // ── sendText ─────────────────────────────────────────────────

  it('sendText delegates to meta-api sendTextMessage', async () => {
    mockSendTextMessage.mockResolvedValueOnce({ messageId: 'wamid-1' });

    const result = await adapter.sendText({ to: '123', text: 'Hello' });

    expect(mockSendTextMessage).toHaveBeenCalledTimes(1);
    expect(mockSendTextMessage).toHaveBeenCalledWith({
      to: '123',
      text: 'Hello',
      previewUrl: undefined,
      accessToken: BASE_CONFIG.accessToken,
      phoneNumberId: BASE_CONFIG.phoneNumberId,
    });
    expect(result).toEqual({ messageId: 'wamid-1' });
  });

  it('sendText passes override accessToken and phoneNumberId when provided', async () => {
    mockSendTextMessage.mockResolvedValueOnce({ messageId: 'wamid-2' });

    const result = await adapter.sendText({
      to: '456',
      text: 'Override',
      accessToken: 'override-token',
      phoneNumberId: 'override-phone',
    });

    expect(mockSendTextMessage).toHaveBeenCalledWith({
      to: '456',
      text: 'Override',
      previewUrl: undefined,
      accessToken: 'override-token',
      phoneNumberId: 'override-phone',
    });
    expect(result).toEqual({ messageId: 'wamid-2' });
  });

  // ── sendMedia ────────────────────────────────────────────────

  it('sendMedia delegates to meta-api sendMediaMessage', async () => {
    mockSendMediaMessage.mockResolvedValueOnce({ messageId: 'wamid-media' });

    const result = await adapter.sendMedia({
      to: '789',
      mediaType: 'image',
      mediaUrl: 'https://example.com/img.jpg',
      caption: 'Nice pic',
    });

    expect(mockSendMediaMessage).toHaveBeenCalledTimes(1);
    expect(mockSendMediaMessage).toHaveBeenCalledWith({
      to: '789',
      kind: 'image',
      link: 'https://example.com/img.jpg',
      caption: 'Nice pic',
      filename: undefined,
      accessToken: BASE_CONFIG.accessToken,
      phoneNumberId: BASE_CONFIG.phoneNumberId,
    });
    expect(result).toEqual({ messageId: 'wamid-media' });
  });

  // ── sendTemplate ─────────────────────────────────────────────

  it('sendTemplate delegates to meta-api sendTemplateMessage', async () => {
    mockSendTemplateMessage.mockResolvedValueOnce({ messageId: 'wamid-tpl' });

    const result = await adapter.sendTemplate({
      to: '111',
      templateName: 'welcome',
      templateLanguage: 'en_US',
    });

    expect(mockSendTemplateMessage).toHaveBeenCalledTimes(1);
    expect(mockSendTemplateMessage).toHaveBeenCalledWith({
      to: '111',
      templateName: 'welcome',
      language: 'en_US',
      params: [],
      messageParams: undefined,
      template: undefined,
      accessToken: BASE_CONFIG.accessToken,
      phoneNumberId: BASE_CONFIG.phoneNumberId,
    });
    expect(result).toEqual({ messageId: 'wamid-tpl' });
  });

  // ── sendInteractiveButtons ───────────────────────────────────

  it('sendInteractiveButtons delegates to meta-api sendInteractiveButtons', async () => {
    mockSendInteractiveButtons.mockResolvedValueOnce({ messageId: 'wamid-btn' });

    const result = await adapter.sendInteractiveButtons({
      to: '222',
      bodyText: 'Choose one',
      buttons: [
        { id: 'yes', title: 'Yes' },
        { id: 'no', title: 'No' },
      ],
    });

    expect(mockSendInteractiveButtons).toHaveBeenCalledTimes(1);
    expect(mockSendInteractiveButtons).toHaveBeenCalledWith({
      to: '222',
      bodyText: 'Choose one',
      headerText: undefined,
      footerText: undefined,
      buttons: [
        { id: 'yes', title: 'Yes' },
        { id: 'no', title: 'No' },
      ],
      accessToken: BASE_CONFIG.accessToken,
      phoneNumberId: BASE_CONFIG.phoneNumberId,
    });
    expect(result).toEqual({ messageId: 'wamid-btn' });
  });

  // ── sendInteractiveList ──────────────────────────────────────

  it('sendInteractiveList delegates to meta-api sendInteractiveList', async () => {
    mockSendInteractiveList.mockResolvedValueOnce({ messageId: 'wamid-list' });

    const result = await adapter.sendInteractiveList({
      to: '333',
      bodyText: 'Pick a product',
      buttonText: 'View',
      sections: [
        {
          title: 'Category A',
          rows: [
            { id: 'p1', title: 'Product 1' },
          ],
        },
      ],
    });

    expect(mockSendInteractiveList).toHaveBeenCalledTimes(1);
    expect(mockSendInteractiveList).toHaveBeenCalledWith({
      to: '333',
      bodyText: 'Pick a product',
      buttonLabel: 'View',
      headerText: undefined,
      footerText: undefined,
      sections: [
        {
          title: 'Category A',
          rows: [{ id: 'p1', title: 'Product 1' }],
        },
      ],
      accessToken: BASE_CONFIG.accessToken,
      phoneNumberId: BASE_CONFIG.phoneNumberId,
    });
    expect(result).toEqual({ messageId: 'wamid-list' });
  });

  // ── sendReaction ─────────────────────────────────────────────

  it('sendReaction delegates to meta-api sendReactionMessage', async () => {
    mockSendReactionMessage.mockResolvedValueOnce({ messageId: 'wamid-react' });

    const result = await adapter.sendReaction({
      to: '444',
      messageId: 'wamid-target',
      emoji: '👍',
    });

    expect(mockSendReactionMessage).toHaveBeenCalledTimes(1);
    expect(mockSendReactionMessage).toHaveBeenCalledWith({
      to: '444',
      targetMessageId: 'wamid-target',
      emoji: '👍',
      accessToken: BASE_CONFIG.accessToken,
      phoneNumberId: BASE_CONFIG.phoneNumberId,
    });
    expect(result).toEqual({ messageId: 'wamid-react' });
  });

  // ── processWebhook ───────────────────────────────────────────

  it('processWebhook parses a Meta message webhook event', async () => {
    const payload = {
      object: 'whatsapp_business_account',
      entry: [
        {
          id: 'waba-id',
          changes: [
            {
              value: {
                messaging_product: 'whatsapp',
                metadata: { phone_number_id: 'phone-id' },
                contacts: [{ wa_id: '5551234' }],
                messages: [
                  {
                    from: '5551234',
                    id: 'wamid-incoming',
                    type: 'text',
                    text: { body: 'Hello from customer' },
                    timestamp: '1700000000',
                  },
                ],
              },
              field: 'messages',
            },
          ],
        },
      ],
    };

    const events = await adapter.processWebhook(payload);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('message');
    expect(events[0].payload).toMatchObject({
      from: '5551234',
      messageId: 'wamid-incoming',
    });
  });

  it('processWebhook parses a status update webhook event', async () => {
    const payload = {
      object: 'whatsapp_business_account',
      entry: [
        {
          id: 'waba-id',
          changes: [
            {
              value: {
                messaging_product: 'whatsapp',
                metadata: { phone_number_id: 'phone-id' },
                statuses: [
                  {
                    id: 'wamid-status',
                    status: 'sent',
                    timestamp: '1700000000',
                    recipient_id: '5551234',
                  },
                ],
              },
              field: 'messages',
            },
          ],
        },
      ],
    };

    const events = await adapter.processWebhook(payload);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('status');
  });

  it('processWebhook returns empty array for unrecognized payloads', async () => {
    const events = await adapter.processWebhook({ foo: 'bar' });
    expect(events).toEqual([]);
  });

  it('processWebhook returns empty array for null entry', async () => {
    const events = await adapter.processWebhook({ object: 'whatsapp_business_account' });
    expect(events).toEqual([]);
  });

  // ── verifyRequest ────────────────────────────────────────────

  it('verifyRequest delegates to verifyMetaWebhookSignature', () => {
    const result = adapter.verifyRequest('sha256=valid-hmac', '{"key":"value"}');
    expect(result).toBe(true);
  });

  it('verifyRequest returns false for invalid signature', () => {
    const result = adapter.verifyRequest('sha256=bad-hmac', '{"key":"value"}');
    expect(result).toBe(false);
  });

  // ── getProviderStatus ────────────────────────────────────────

  it('getProviderStatus returns connected=true when verifyPhoneNumber succeeds', async () => {
    mockVerifyPhoneNumber.mockResolvedValueOnce({
      id: 'phone-id',
      display_phone_number: '+15551234567',
      verified_name: 'Test Business',
      quality_rating: 'GREEN',
    });

    const status = await adapter.getProviderStatus();

    expect(mockVerifyPhoneNumber).toHaveBeenCalledWith({
      phoneNumberId: BASE_CONFIG.phoneNumberId,
      accessToken: BASE_CONFIG.accessToken,
    });
    expect(status.connected).toBe(true);
    expect(status.label).toBe('Meta Cloud API');
    expect(status.lastChecked).toBeDefined();
  });

  it('getProviderStatus returns connected=false when verifyPhoneNumber throws', async () => {
    mockVerifyPhoneNumber.mockRejectedValueOnce(new Error('API error'));

    const status = await adapter.getProviderStatus();

    expect(status.connected).toBe(false);
    expect(status.label).toBe('Meta Cloud API');
    expect(status.lastChecked).toBeDefined();
  });
});
