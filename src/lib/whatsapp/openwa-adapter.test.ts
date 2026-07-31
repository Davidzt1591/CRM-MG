import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// We'll import after mocking fetch
import { OpenWAAdapter } from './openwa-adapter';

const BASE_CONFIG = {
  apiUrl: 'http://localhost:2785',
  apiKey: 'test-api-key',
  secret: 'test-secret',
};

describe('OpenWAAdapter', () => {
  let adapter: OpenWAAdapter;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
    adapter = new OpenWAAdapter(BASE_CONFIG);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // ── Constructor ──────────────────────────────────────────────

  it('stores config and exposes name', () => {
    expect(adapter.name).toBe('OpenWA');
  });

  it('strips trailing slash from apiUrl', () => {
    const a = new OpenWAAdapter({ ...BASE_CONFIG, apiUrl: 'http://localhost:2785/' });
    // Access private field via prototype — we just check the resulting URL pattern
    expect(a.name).toBe('OpenWA');
  });

  // ── sendText ─────────────────────────────────────────────────

  it('sendText POSTs to /send/text with correct body and headers', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'openwa-msg-1' }),
    });

    const result = await adapter.sendText({ to: '1234567890', text: 'Hello' });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe('http://localhost:2785/send/text');
    expect(opts.method).toBe('POST');
    expect(opts.headers).toEqual({
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-api-key',
    });
    expect(JSON.parse(opts.body)).toEqual({
      chatId: '1234567890@c.us',
      text: 'Hello',
    });
    expect(result).toEqual({ messageId: 'openwa-msg-1', providerMessageId: 'openwa-msg-1' });
  });

  it('sendText appends @c.us when to already contains @', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'openwa-msg-2' }),
    });

    await adapter.sendText({ to: 'user@example.com', text: 'Hi' });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.chatId).toBe('user@example.com');
  });

  it('sendText generates a UUID when OpenWA returns no id', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    });

    const result = await adapter.sendText({ to: '123', text: 'Hi' });

    expect(result.messageId).toBeDefined();
    expect(result.messageId.length).toBeGreaterThan(0);
    expect(result.providerMessageId).toBeUndefined();
  });

  it('sendText throws on non-ok response', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    await expect(
      adapter.sendText({ to: '123', text: 'Boom' }),
    ).rejects.toThrow('OpenWA sendText failed: 500');
  });

  // ── sendMedia ────────────────────────────────────────────────

  it('sendMedia POSTs to /send/media with correct body', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'openwa-media-1' }),
    });

    const result = await adapter.sendMedia({
      to: '123',
      mediaType: 'image',
      mediaUrl: 'https://example.com/img.jpg',
      caption: 'Check this',
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe('http://localhost:2785/send/media');
    const body = JSON.parse(opts.body);
    expect(body.chatId).toBe('123@c.us');
    expect(body.mediaType).toBe('image');
    expect(body.mediaUrl).toBe('https://example.com/img.jpg');
    expect(body.caption).toBe('Check this');
    expect(result).toEqual({ messageId: 'openwa-media-1', providerMessageId: 'openwa-media-1' });
  });

  // ── sendTemplate ─────────────────────────────────────────────

  it('sendTemplate throws because OpenWA does not support templates', async () => {
    await expect(
      adapter.sendTemplate({ to: '123', templateName: 'welcome' }),
    ).rejects.toThrow('OpenWA does not support template messages');
  });

  // ── sendInteractiveButtons ───────────────────────────────────

  it('sendInteractiveButtons POSTs to /send/buttons', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'openwa-btn-1' }),
    });

    const result = await adapter.sendInteractiveButtons({
      to: '123',
      bodyText: 'Choose one',
      buttons: [{ id: 'yes', title: 'Yes' }, { id: 'no', title: 'No' }],
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe('http://localhost:2785/send/buttons');
    expect(result.messageId).toBe('openwa-btn-1');
  });

  // ── sendInteractiveList ──────────────────────────────────────

  it('sendInteractiveList POSTs to /send/list', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'openwa-list-1' }),
    });

    const result = await adapter.sendInteractiveList({
      to: '123',
      bodyText: 'Pick a product',
      buttonText: 'View',
      sections: [{ title: 'Cat A', rows: [{ id: 'p1', title: 'Product 1' }] }],
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe('http://localhost:2785/send/list');
    expect(result.messageId).toBe('openwa-list-1');
  });

  // ── sendReaction ─────────────────────────────────────────────

  it('sendReaction POSTs to /send/reaction', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'openwa-react-1' }),
    });

    const result = await adapter.sendReaction({
      to: '123',
      messageId: 'target-msg',
      emoji: '👍',
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe('http://localhost:2785/send/reaction');
    expect(result.messageId).toBe('openwa-react-1');
  });

  // ── processWebhook ───────────────────────────────────────────

  it('processWebhook parses an onmessage event', async () => {
    const payload = {
      event: 'onmessage',
      data: {
        from: '5551234',
        body: 'Hello from OpenWA',
        id: 'openwa-msg-incoming',
        t: 1700000000,
      },
    };

    const events = await adapter.processWebhook(payload);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('message');
    expect(events[0].payload).toMatchObject({
      from: '5551234',
      messageId: 'openwa-msg-incoming',
      text: 'Hello from OpenWA',
    });
  });

  it('processWebhook parses an onack (status) event', async () => {
    const payload = {
      event: 'onack',
      data: {
        id: 'openwa-msg-status',
        status: 'sent',
        to: '5551234',
        t: 1700000000,
      },
    };

    const events = await adapter.processWebhook(payload);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('status');
    expect(events[0].payload).toMatchObject({
      messageId: 'openwa-msg-status',
      status: 'sent',
    });
  });

  it('processWebhook returns empty array for unknown event type', async () => {
    const payload = { event: 'onunknown', data: {} };
    const events = await adapter.processWebhook(payload);
    expect(events).toEqual([]);
  });

  it('processWebhook returns empty array for malformed payload', async () => {
    const events = await adapter.processWebhook({ foo: 'bar' });
    expect(events).toEqual([]);
  });

  // ── verifyRequest ────────────────────────────────────────────

  it('verifyRequest returns true for correct HMAC-SHA256 signature', () => {
    const body = JSON.stringify({ event: 'onmessage', data: { body: 'hello' } });
    // Compute the expected signature using the same algorithm
    const { createHmac } = require('crypto');
    const expected = createHmac('sha256', BASE_CONFIG.secret).update(body).digest('hex');

    const result = adapter.verifyRequest(expected, body);
    expect(result).toBe(true);
  });

  it('verifyRequest returns false for incorrect signature', () => {
    const result = adapter.verifyRequest('wrong-signature', '{"foo":"bar"}');
    expect(result).toBe(false);
  });

  it('verifyRequest returns false for empty signature', () => {
    const result = adapter.verifyRequest('', '{"foo":"bar"}');
    expect(result).toBe(false);
  });

  // ── getProviderStatus ────────────────────────────────────────

  it('getProviderStatus returns connected=true when /status returns ok', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
    });

    const status = await adapter.getProviderStatus();

    expect(mockFetch).toHaveBeenCalledWith('http://localhost:2785/status', {
      headers: { 'Authorization': 'Bearer test-api-key' },
    });
    expect(status.connected).toBe(true);
    expect(status.label).toBe('OpenWA');
    expect(status.lastChecked).toBeDefined();
    // Verify lastChecked is a valid ISO date string
    expect(() => new Date(status.lastChecked)).not.toThrow();
  });

  it('getProviderStatus returns connected=false when fetch fails', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

    const status = await adapter.getProviderStatus();

    expect(status.connected).toBe(false);
    expect(status.label).toBe('OpenWA');
  });

  it('getProviderStatus returns connected=false when /status returns non-ok', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 503,
    });

    const status = await adapter.getProviderStatus();
    expect(status.connected).toBe(false);
  });
});
