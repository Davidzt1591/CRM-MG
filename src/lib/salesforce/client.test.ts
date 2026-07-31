import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SalesforceClient } from './client';
import { decrypt } from '@/lib/whatsapp/encryption';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Mock encryption — we need to know what decrypt returns to build assertions
vi.mock('@/lib/whatsapp/encryption', () => ({
  decrypt: vi.fn((input: string) => `decrypted-${input}`),
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ENCRYPTED_CONFIG = {
  id: 'cfg-1',
  account_id: 'acct-1',
  instance_url: 'https://magneto-dev-ed.my.salesforce.com/',
  is_sandbox: true,
  client_id: 'sf-client-id-enc',
  client_secret: 'sf-client-secret-enc',
  username: 'admin@magneto.crm.enc',
  password: 'p@ssw0rd-enc',
  security_token: 'sf-token-enc',
  connected_at: '2026-07-30T12:00:00Z',
};

const DECRYPTED = {
  clientId: 'decrypted-sf-client-id-enc',
  clientSecret: 'decrypted-sf-client-secret-enc',
  username: 'decrypted-admin@magneto.crm.enc',
  password: 'decrypted-p@ssw0rd-enc',
  securityToken: 'decrypted-sf-token-enc',
};

const OAUTH_TOKEN_RESPONSE = {
  access_token: '00D5g00000ABCde!abc123',
  instance_url: 'https://magneto-dev-ed.my.salesforce.com',
  id: 'https://test.salesforce.com/id/org/user',
  token_type: 'Bearer',
  issued_at: '1722345678000',
  signature: 'fake-signature',
};

const MOCK_CASE = {
  Id: '5005g00001ABCDEFGHI',
  CaseNumber: '00001001',
  Status: 'New',
  Subject: 'Test Case',
  Description: 'A test case for TDD',
  ContactId: '0035g00001ABCDEFGHI',
  AccountId: '0015g00001ABCDEFGHI',
  CreatedDate: '2026-07-30T14:00:00.000+0000',
};

const MOCK_FEED_ITEM = {
  Id: '0D55g00001ABCDEFGHI',
  Body: 'This is a case note',
  CreatedDate: '2026-07-30T14:05:00.000+0000',
  CreatedBy: { Name: 'Admin User' },
};

const MOCK_SEARCH_RESULT = {
  searchRecords: [MOCK_CASE],
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Configure mockFetch to respond to a Salesforce OAuth2 token endpoint.
 * Returns the response body so tests can verify it was passed correctly.
 */
function mockOAuth() {
  mockFetch.mockImplementationOnce(async (url: string, opts: RequestInit) => {
    if (url.endsWith('/services/oauth2/token')) {
      const body = opts.body as URLSearchParams;
      return {
        ok: true,
        status: 200,
        json: async () => OAUTH_TOKEN_RESPONSE,
        headers: new Headers({ 'Content-Type': 'application/json' }),
      };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  });
}

/**
 * Configure mockFetch to respond to an authenticated Salesforce API call.
 * Also verifies the Authorization header was set correctly.
 */
function mockApiResponse(response: unknown, status = 200) {
  mockFetch.mockImplementationOnce(async (url: string, opts: RequestInit) => {
    const headers = opts.headers as Record<string, string>;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => response,
      headers: new Headers({ 'Content-Type': 'application/json' }),
    };
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SalesforceClient', () => {
  let client: SalesforceClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new SalesforceClient(ENCRYPTED_CONFIG);
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  // ── Constructor ──────────────────────────────────────────────

  describe('constructor', () => {
    it('decrypts secrets and strips trailing slashes from instance_url', () => {
      expect((client as any).config.instanceUrl).toBe(
        'https://magneto-dev-ed.my.salesforce.com',
      );
      expect(decrypt).toHaveBeenCalledWith(ENCRYPTED_CONFIG.client_id);
      expect(decrypt).toHaveBeenCalledWith(ENCRYPTED_CONFIG.client_secret);
      expect(decrypt).toHaveBeenCalledWith(ENCRYPTED_CONFIG.username);
      expect(decrypt).toHaveBeenCalledWith(ENCRYPTED_CONFIG.password);
      expect(decrypt).toHaveBeenCalledWith(ENCRYPTED_CONFIG.security_token);
    });

    it('exposes core config values after construction', () => {
      expect((client as any).config.isSandbox).toBe(true);
      expect((client as any).config.accountId).toBe('acct-1');
    });
  });

  // ── OAuth2 Authentication ───────────────────────────────────

  describe('authenticate', () => {
    it('exchanges credentials for an access token via OAuth2 password flow', async () => {
      mockOAuth();

      const token = await (client as any).authenticate();

      expect(token).toBe(OAUTH_TOKEN_RESPONSE.access_token);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const callUrl = mockFetch.mock.calls[0][0];
      expect(callUrl).toContain('/services/oauth2/token');

      const callOpts = mockFetch.mock.calls[0][1];
      const body = callOpts.body as URLSearchParams;
      expect(body.get('grant_type')).toBe('password');
      expect(body.get('client_id')).toBe(DECRYPTED.clientId);
      expect(body.get('client_secret')).toBe(DECRYPTED.clientSecret);
      expect(body.get('username')).toBe(DECRYPTED.username);
      expect(body.get('password')).toBe(DECRYPTED.password + DECRYPTED.securityToken);
    });

    it('caches the access token and does not re-authenticate on subsequent calls', async () => {
      mockOAuth();

      await (client as any).authenticate();
      await (client as any).authenticate();
      await (client as any).authenticate();

      // Fetch should only be called once — subsequent calls use the cached token
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  // ── createCase ───────────────────────────────────────────────

  describe('createCase', () => {
    it('creates a Case via POST and returns the Salesforce record', async () => {
      mockOAuth();
      mockApiResponse(MOCK_CASE);

      const result = await client.createCase({
        subject: 'Test Case',
        description: 'A test case',
        origin: 'WhatsApp',
      });

      expect(result).toEqual(MOCK_CASE);

      // Verify the POST body
      const postCall = mockFetch.mock.calls[1];
      expect(postCall[0]).toContain('/services/data/v62.0/sobjects/Case');
      expect(postCall[1].method).toBe('POST');
      const body = JSON.parse(postCall[1].body as string);
      expect(body.Subject).toBe('Test Case');
      expect(body.Description).toBe('A test case');
      expect(body.Origin).toBe('WhatsApp');
      expect(body.Status).toBe('New');
    });

    it('passes optional contactId and accountId when provided', async () => {
      mockOAuth();
      mockApiResponse({ ...MOCK_CASE, ContactId: '003xxx', AccountId: '001xxx' });

      await client.createCase({
        subject: 'Case with refs',
        contactId: '003xxx',
        accountId: '001xxx',
      });

      const postBody = JSON.parse(mockFetch.mock.calls[1][1].body as string);
      expect(postBody.ContactId).toBe('003xxx');
      expect(postBody.AccountId).toBe('001xxx');
    });
  });

  // ── updateCase ───────────────────────────────────────────────

  describe('updateCase', () => {
    it('updates a Case via PATCH', async () => {
      mockOAuth();
      mockApiResponse(null, 204);

      await client.updateCase('5005g00001ABCDEFGHI', {
        Status: 'In Progress',
        Subject: 'Updated Subject',
      });

      const patchCall = mockFetch.mock.calls[1];
      expect(patchCall[0]).toContain('/services/data/v62.0/sobjects/Case/5005g00001ABCDEFGHI');
      expect(patchCall[1].method).toBe('PATCH');
      const body = JSON.parse(patchCall[1].body as string);
      expect(body.Status).toBe('In Progress');
      expect(body.Subject).toBe('Updated Subject');
    });
  });

  // ── getCase ──────────────────────────────────────────────────

  describe('getCase', () => {
    it('retrieves a Case by ID via GET', async () => {
      mockOAuth();
      mockApiResponse(MOCK_CASE);

      const result = await client.getCase('5005g00001ABCDEFGHI');

      expect(result).toEqual(MOCK_CASE);
      const getCall = mockFetch.mock.calls[1];
      expect(getCall[0]).toContain('/services/data/v62.0/sobjects/Case/5005g00001ABCDEFGHI');
      expect(getCall[1].method).toBe('GET');
    });
  });

  // ── postFeedItem ─────────────────────────────────────────────

  describe('postFeedItem', () => {
    it('posts a FeedItem to a Case via POST', async () => {
      mockOAuth();
      mockApiResponse(MOCK_FEED_ITEM);

      const result = await client.postFeedItem('5005g00001ABCDEFGHI', 'This is a note');

      expect(result).toEqual(MOCK_FEED_ITEM);
      const postCall = mockFetch.mock.calls[1];
      expect(postCall[0]).toContain('/services/data/v62.0/sobjects/FeedItem');
      expect(postCall[1].method).toBe('POST');
      const body = JSON.parse(postCall[1].body as string);
      expect(body.ParentId).toBe('5005g00001ABCDEFGHI');
      expect(body.Body).toBe('This is a note');
      expect(body.Type).toBe('TextPost');
    });
  });

  // ── searchCases ──────────────────────────────────────────────

  describe('searchCases', () => {
    it('searches cases via SOSL and returns matching records', async () => {
      mockOAuth();
      mockApiResponse(MOCK_SEARCH_RESULT);

      const result = await client.searchCases('FIND {test} IN ALL FIELDS');

      expect(result).toEqual([MOCK_CASE]);
      const getCall = mockFetch.mock.calls[1];
      expect(getCall[0]).toContain('/services/data/v62.0/search');
      expect(getCall[0]).toContain(encodeURIComponent('FIND {test} IN ALL FIELDS'));
    });
  });

  // ── testConnection ───────────────────────────────────────────

  describe('testConnection', () => {
    it('returns success when OAuth2 authentication succeeds', async () => {
      mockOAuth();

      const result = await client.testConnection();

      expect(result.success).toBe(true);
      expect(result.message).toBe('Connected successfully');
    });

    it('returns failure with error message when authentication fails', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const result = await client.testConnection();

      expect(result.success).toBe(false);
      expect(result.message).toBe('Network error');
    });
  });

  // ── 401 re-authentication ────────────────────────────────────

  describe('401 retry', () => {
    it('re-authenticates and retries the request once on 401', async () => {
      // First OAuth succeeds
      mockOAuth();
      // First API call returns 401
      mockApiResponse({ error: 'invalid_session_id' }, 401);
      // Second OAuth (re-auth)
      mockOAuth();
      // Retry succeeds
      mockApiResponse(MOCK_CASE);

      const result = await client.getCase('5005g00001ABCDEFGHI');

      expect(result).toEqual(MOCK_CASE);
      // OAuth called twice (initial + re-auth), API called twice (401 + retry)
      expect(mockFetch).toHaveBeenCalledTimes(4);
    });
  });
});
