import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SupabaseClient } from '@supabase/supabase-js';

import {
  sendMessageToConversation,
  SendMessageError,
  type SendMessageParams,
} from './send-message';

// A db that explodes if touched — these tests cover the param
// validation that MUST short-circuit before any query runs.
function noDb(): SupabaseClient {
  return {
    from() {
      throw new Error('db should not be queried for invalid params');
    },
  } as unknown as SupabaseClient;
}

async function expectSendError(
  params: SendMessageParams,
  status: number,
  messageMatch?: RegExp
) {
  await expect(
    sendMessageToConversation(noDb(), 'acct-1', params)
  ).rejects.toBeInstanceOf(SendMessageError);
  await sendMessageToConversation(noDb(), 'acct-1', params).catch(
    (e: SendMessageError) => {
      expect(e.status).toBe(status);
      if (messageMatch) expect(e.message).toMatch(messageMatch);
    }
  );
}

describe('sendMessageToConversation — param validation (pre-DB)', () => {
  const base = { conversationId: 'cv-1' };

  it('requires conversation_id and message_type', async () => {
    await expectSendError({ conversationId: '', messageType: 'text' }, 400);
    await expectSendError({ conversationId: 'cv-1', messageType: '' }, 400);
  });

  it('rejects an unsupported message_type', async () => {
    await expectSendError(
      { ...base, messageType: 'carrier-pigeon' },
      400,
      /Unsupported message_type/
    );
  });

  it('requires content_text for text messages', async () => {
    await expectSendError(
      { ...base, messageType: 'text' },
      400,
      /content_text is required/
    );
  });

  it('requires template_name for template messages', async () => {
    await expectSendError(
      { ...base, messageType: 'template' },
      400,
      /template_name is required/
    );
  });

  it('requires media_url for media kinds', async () => {
    for (const kind of ['image', 'video', 'document', 'audio']) {
      await expectSendError(
        { ...base, messageType: kind },
        400,
        /media_url is required/
      );
    }
  });

  it('rejects an over-long media caption (non-audio)', async () => {
    await expectSendError(
      {
        ...base,
        messageType: 'image',
        mediaUrl: 'https://x/y.jpg',
        contentText: 'a'.repeat(1025),
      },
      400,
      /1024-character limit/
    );
  });

  it('requires a valid interactive payload for interactive messages', async () => {
    // Missing payload entirely.
    await expectSendError(
      { ...base, messageType: 'interactive' },
      400,
      /payload is required/
    );
    // Too many buttons.
    await expectSendError(
      {
        ...base,
        messageType: 'interactive',
        interactivePayload: {
          kind: 'buttons',
          body: 'Pick one',
          buttons: [
            { id: 'a', title: 'A' },
            { id: 'b', title: 'B' },
            { id: 'c', title: 'C' },
            { id: 'd', title: 'D' },
          ],
        },
      },
      400,
      /at most 3 buttons/
    );
    // Over-long button title.
    await expectSendError(
      {
        ...base,
        messageType: 'interactive',
        interactivePayload: {
          kind: 'buttons',
          body: 'Pick one',
          buttons: [{ id: 'a', title: 'x'.repeat(21) }],
        },
      },
      400,
      /20-character limit/
    );
  });

  it('allows a long "caption" on audio (audio carries none) — so it reaches the DB', async () => {
    // Audio is exempt from the caption cap, so validation passes and we
    // proceed to the conversation lookup — proven by the stub throwing.
    const spy = vi.fn(() => {
      throw new Error('reached DB');
    });
    const db = { from: spy } as unknown as SupabaseClient;
    await expect(
      sendMessageToConversation(db, 'acct-1', {
        ...base,
        messageType: 'audio',
        mediaUrl: 'https://x/y.ogg',
        contentText: 'a'.repeat(2000),
      })
    ).rejects.toThrow('reached DB');
    expect(spy).toHaveBeenCalledWith('conversations');
  });
});

describe('SendMessageError', () => {
  it('carries a machine code and an HTTP status', () => {
    const e = new SendMessageError('meta_error', 'boom', 502);
    expect(e.code).toBe('meta_error');
    expect(e.status).toBe(502);
    expect(e).toBeInstanceOf(Error);
  });
});

// ---------------------------------------------------------------------------
// Provider-routing tests — verify that sendMessageToConversation routes
// through getProvider() instead of calling meta-api functions directly.
// ---------------------------------------------------------------------------

// Mock encryption to avoid decrypt failures during provider-routing tests.
vi.mock('@/lib/whatsapp/encryption', () => ({
  decrypt: () => 'test-decrypted-token',
  encrypt: (v: string) => v,
  isLegacyFormat: () => false,
}));

// Mock supabaseAdmin so the "pause active flow runs" step doesn't make a
// real HTTP request (which would hang because no Supabase is running).
vi.mock('@/lib/flows/admin-client', () => ({
  supabaseAdmin: () => ({
    from: () => ({
      update: () => ({
        eq: () => ({
          eq: () => ({
            eq: () => Promise.resolve({ error: null }),
          }),
        }),
      }),
    }),
  }),
}));

// Mock getProvider to return a controllable mock adapter.
const mockSendText = vi.fn();
const mockSendMedia = vi.fn();
const mockSendTemplate = vi.fn();
const mockSendInteractiveButtons = vi.fn();
const mockSendInteractiveList = vi.fn();

vi.mock('@/lib/whatsapp/provider-registry', () => ({
  getProvider: () => ({
    name: 'Meta Cloud API',
    sendText: (...args: unknown[]) => mockSendText(...args),
    sendMedia: (...args: unknown[]) => mockSendMedia(...args),
    sendTemplate: (...args: unknown[]) => mockSendTemplate(...args),
    sendInteractiveButtons: (...args: unknown[]) => mockSendInteractiveButtons(...args),
    sendInteractiveList: (...args: unknown[]) => mockSendInteractiveList(...args),
    sendReaction: vi.fn(),
    processWebhook: vi.fn(),
    verifyRequest: vi.fn(),
    getProviderStatus: vi.fn(),
  }),
}));

describe('sendMessageToConversation — provider routing', () => {
  const conversationId = 'cv-1';

  /**
   * Build a lightweight mock Supabase client. Each `from(table)` returns
   * a chain proxy where all methods (`select`, `eq`, `update`, `insert`,
   * etc.) return the chain itself, and terminal methods (`single`,
   * `maybeSingle`) return a canned Promise.
   *
   * IMPORTANT: the chain proxy delegates `.then` and `.catch` to the
   * underlying terminal Promise so that `await` works even when the
   * caller doesn't use `.single()` (e.g. `await db.from('t').update(x)
   * .eq('id', y)` — Supabase builders are thenable).
   */
  function mockDb(): SupabaseClient {
    function chain(terminal: Promise<unknown>) {
      return new Proxy(terminal, {
        get(target: Promise<unknown>, prop: string) {
          if (prop === 'single' || prop === 'maybeSingle') return () => target;
          // Delegate then/catch so `await chain(…)` resolves the terminal.
          if (prop === 'then' || prop === 'catch') {
            const val = Reflect.get(target, prop);
            return typeof val === 'function' ? val.bind(target) : val;
          }
          // All other methods return a new chain link.
          return () => chain(target);
        },
      });
    }

    // Pre-resolved promises for each query path.
    const resolveConversation = Promise.resolve({
      data: {
        id: conversationId,
        contact: { id: 'contact-1', phone: '+15551234567' },
      },
      error: null,
    });
    const resolveConfig = Promise.resolve({
      data: {
        id: 'config-1',
        phone_number_id: 'phone-id',
        access_token: 'gcm-iv:ct:tag',
        provider: 'meta',
        provider_config: null,
      },
      error: null,
    });
    const resolveNull = Promise.resolve({ data: null, error: null });
    const resolveInsert = Promise.resolve({ data: { id: 'msg-1' }, error: null });
    const resolveUpdate = Promise.resolve({ error: null });

    // send-message.ts accesses each table in a predictable order.
    // We return a different terminal promise based on call count.
    const callSeq = new Map<string, number>();

    const from = vi.fn((table: string) => {
      const n = (callSeq.get(table) ?? 0) + 1;
      callSeq.set(table, n);

      switch (table) {
        case 'conversations':
          return chain(n === 1 ? resolveConversation : resolveUpdate);
        case 'contacts':
          return chain(resolveUpdate);
        case 'whatsapp_config':
          return chain(resolveConfig);
        case 'messages':
          // None of our tests set replyToMessageId, so the first call
          // to messages is always the insert (not a reply lookup).
          return chain(resolveInsert);
        case 'message_templates':
          return chain(resolveNull);
        case 'flow_runs':
          return chain(resolveUpdate); // try/catch on pause
        default:
          return chain(Promise.resolve({ data: null, error: null }));
      }
    });
    return { from } as unknown as SupabaseClient;
  }

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('routes a text send through provider.sendText', async () => {
    mockSendText.mockResolvedValueOnce({ messageId: 'wamid-text' });

    const result = await sendMessageToConversation(mockDb(), 'acct-1', {
      conversationId,
      messageType: 'text',
      contentText: 'Hello from agent',
    });

    expect(result.messageId).toBe('msg-1');
    expect(mockSendText).toHaveBeenCalledTimes(1);
    expect(mockSendText).toHaveBeenCalledWith({
      to: '15551234567',
      text: 'Hello from agent',
    });
  }, 10000);

  it('routes a media send through provider.sendMedia', async () => {
    mockSendMedia.mockResolvedValueOnce({ messageId: 'wamid-media' });

    const result = await sendMessageToConversation(mockDb(), 'acct-1', {
      conversationId,
      messageType: 'image',
      mediaUrl: 'https://example.com/pic.jpg',
      contentText: 'See this',
    });

    expect(result.messageId).toBe('msg-1');
    expect(mockSendMedia).toHaveBeenCalledTimes(1);
    expect(mockSendMedia).toHaveBeenCalledWith({
      to: '15551234567',
      mediaType: 'image',
      mediaUrl: 'https://example.com/pic.jpg',
      caption: 'See this',
      filename: undefined,
    });
  }, 10000);

  it('routes a template send through provider.sendTemplate', async () => {
    mockSendTemplate.mockResolvedValueOnce({ messageId: 'wamid-tpl' });

    const result = await sendMessageToConversation(mockDb(), 'acct-1', {
      conversationId,
      messageType: 'template',
      templateName: 'welcome',
      templateLanguage: 'en_US',
    });

    expect(result.messageId).toBe('msg-1');
    expect(mockSendTemplate).toHaveBeenCalledTimes(1);
    expect(mockSendTemplate).toHaveBeenCalledWith({
      to: '15551234567',
      templateName: 'welcome',
      templateLanguage: 'en_US',
      templateParams: undefined,
      templateMessageParams: undefined,
    });
  }, 10000);

  it('routes an interactive buttons send through provider.sendInteractiveButtons', async () => {
    mockSendInteractiveButtons.mockResolvedValueOnce({ messageId: 'wamid-btn' });

    const result = await sendMessageToConversation(mockDb(), 'acct-1', {
      conversationId,
      messageType: 'interactive',
      interactivePayload: {
        kind: 'buttons',
        body: 'Choose',
        buttons: [{ id: 'yes', title: 'Yes' }],
      },
    });

    expect(result.messageId).toBe('msg-1');
    expect(mockSendInteractiveButtons).toHaveBeenCalledTimes(1);
    expect(mockSendInteractiveButtons).toHaveBeenCalledWith({
      to: '15551234567',
      bodyText: 'Choose',
      headerText: undefined,
      footerText: undefined,
      buttons: [{ id: 'yes', title: 'Yes' }],
    });
  }, 10000);

  it('routes an interactive list send through provider.sendInteractiveList', async () => {
    mockSendInteractiveList.mockResolvedValueOnce({ messageId: 'wamid-list' });

    const result = await sendMessageToConversation(mockDb(), 'acct-1', {
      conversationId,
      messageType: 'interactive',
      interactivePayload: {
        kind: 'list',
        body: 'Pick',
        button_label: 'View',
        sections: [{ title: 'A', rows: [{ id: 'a1', title: 'Item 1' }] }],
      },
    });

    expect(result.messageId).toBe('msg-1');
    expect(mockSendInteractiveList).toHaveBeenCalledTimes(1);
    expect(mockSendInteractiveList).toHaveBeenCalledWith({
      to: '15551234567',
      bodyText: 'Pick',
      buttonText: 'View',
      sections: [{ title: 'A', rows: [{ id: 'a1', title: 'Item 1' }] }],
      headerText: undefined,
      footerText: undefined,
    });
  }, 10000);
});

