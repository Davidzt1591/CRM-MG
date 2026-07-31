import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ---------------------------------------------------------------------------
// Mutable mock supabase chain
// ---------------------------------------------------------------------------

const mockSupabaseChain: Record<string, unknown> = {};
function buildChain() {
  const methods = ['from', 'select', 'eq', 'single', 'maybeSingle'] as const;
  for (const m of methods) {
    mockSupabaseChain[m] = vi.fn(() => mockSupabaseChain);
  }
  return mockSupabaseChain;
}
buildChain();

let mockSingleResult: () => Promise<{ data: unknown; error: unknown }> = () =>
  Promise.resolve({ data: null, error: null });
mockSupabaseChain.single = vi.fn(() => mockSingleResult());

vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(() => ({ from: vi.fn(() => mockSupabaseChain) })),
}));

// ---------------------------------------------------------------------------
// Mock the webhook module
// ---------------------------------------------------------------------------

const mockVerify = vi.fn();
const mockProcessCDC = vi.fn();

vi.mock('@/lib/salesforce/webhook', () => ({
  verifySalesforceWebhook: mockVerify,
  processSalesforceCDC: mockProcessCDC,
}));

// ---------------------------------------------------------------------------
// Helper: build a Request for the route
// ---------------------------------------------------------------------------

function buildRequest({
  body,
  signature,
  accountId,
  method = 'POST',
}: {
  body?: unknown;
  signature?: string;
  accountId?: string;
  method?: string;
}): Request {
  const url = accountId
    ? `https://example.com/api/webhooks/salesforce?account_id=${accountId}`
    : 'https://example.com/api/webhooks/salesforce';

  const headers = new Headers({ 'Content-Type': 'application/json' });
  if (signature !== undefined) {
    headers.set('x-salesforce-signature', signature);
  }

  return new Request(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Salesforce Webhook Route', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Default mocks
    mockVerify.mockReturnValue(true);
    mockProcessCDC.mockResolvedValue(undefined);

    // Default: no config found
    mockSingleResult = () =>
      Promise.resolve({ data: null, error: { message: 'not found', code: 'PGRST116' } });
    mockSupabaseChain.single = vi.fn(() => mockSingleResult());
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  // ── POST ──────────────────────────────────────────────────────

  describe('POST', () => {
    it('returns 200 on valid webhook with signature verification and config', async () => {
      // Config found with webhook_secret
      mockSingleResult = () =>
        Promise.resolve({
          data: {
            id: 'cfg-1',
            account_id: 'acct-1',
            instance_url: 'https://magneto-dev-ed.my.salesforce.com',
            webhook_secret: 'whsec_test',
          },
          error: null,
        });
      mockSupabaseChain.single = vi.fn(() => mockSingleResult());

      const { POST } = await import('./route');

      const request = buildRequest({
        body: {
          ChangeEventHeader: {
            entityName: 'Case',
            recordIds: ['500xxx'],
          },
        },
        signature: 'valid-signature-base64',
        accountId: 'acct-1',
      });

      const response = await POST(request);
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json).toEqual({ status: 'received' });

      // Verify that verification was called with the right args
      expect(mockVerify).toHaveBeenCalledWith(
        'valid-signature-base64',
        expect.any(String),
        'whsec_test',
      );

      // Verify that CDC processing was called
      expect(mockProcessCDC).toHaveBeenCalled();
    });

    it('returns 200 with status "received" even when config is not found (graceful)', async () => {
      // Keep default: no config
      const { POST } = await import('./route');

      const request = buildRequest({
        body: {
          ChangeEventHeader: {
            entityName: 'Case',
            recordIds: ['500xxx'],
          },
        },
        signature: 'valid-sig',
        accountId: 'acct-1',
      });

      const response = await POST(request);
      expect(response.status).toBe(200);
    });

    it('returns 401 when signature verification fails', async () => {
      mockVerify.mockReturnValue(false);

      // Config found
      mockSingleResult = () =>
        Promise.resolve({
          data: {
            id: 'cfg-1',
            account_id: 'acct-1',
            instance_url: 'https://magneto-dev-ed.my.salesforce.com',
            webhook_secret: 'whsec_test',
          },
          error: null,
        });
      mockSupabaseChain.single = vi.fn(() => mockSingleResult());

      const { POST } = await import('./route');

      const request = buildRequest({
        body: {
          ChangeEventHeader: {
            entityName: 'Case',
            recordIds: ['500xxx'],
          },
        },
        signature: 'invalid-signature',
        accountId: 'acct-1',
      });

      const response = await POST(request);
      expect(response.status).toBe(401);

      const json = await response.json();
      expect(json).toEqual({ error: 'Invalid signature' });
    });

    it('returns 401 when no signature header is present', async () => {
      const { POST } = await import('./route');

      const request = buildRequest({
        body: {
          ChangeEventHeader: {
            entityName: 'Case',
            recordIds: ['500xxx'],
          },
        },
        accountId: 'acct-1',
      });

      const response = await POST(request);
      expect(response.status).toBe(401);
    });

    it('returns 400 for missing account_id', async () => {
      const { POST } = await import('./route');

      const request = new Request(
        'https://example.com/api/webhooks/salesforce',
        {
          method: 'POST',
          headers: new Headers({
            'Content-Type': 'application/json',
            'x-salesforce-signature': 'sig',
          }),
          body: JSON.stringify({}),
        },
      );

      const response = await POST(request);
      expect(response.status).toBe(400);
    });
  });

  // ── GET (verification) ────────────────────────────────────────

  describe('GET', () => {
    it('returns challenge string when verification params are provided', async () => {
      const { GET } = await import('./route');

      const request = new Request(
        'https://example.com/api/webhooks/salesforce?account_id=acct-1&sf_verify_token=match-token&sf_challenge=abc123',
        { method: 'GET' },
      );

      const response = await GET(request);
      expect(response.status).toBe(200);

      const text = await response.text();
      expect(text).toBe('abc123');
    });

    it('returns 400 when verification parameters are missing', async () => {
      const { GET } = await import('./route');

      const request = new Request(
        'https://example.com/api/webhooks/salesforce',
        { method: 'GET' },
      );

      const response = await GET(request);
      expect(response.status).toBe(400);
    });
  });
});
