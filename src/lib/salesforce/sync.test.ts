import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { SalesforceCase, SalesforceFeedItem } from './client';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

/**
 * Build a chainable Supabase mock. Each method returns the same mock
 * object so `from().select().eq().single()` works.
 */
function mockSupabaseChain(
  singleResult: () => Promise<{ data: unknown; error: unknown }>,
) {
  const chain: Record<string, unknown> = {};
  const methods = ['from', 'select', 'insert', 'update', 'eq'] as const;
  for (const m of methods) {
    chain[m] = vi.fn(() => chain);
  }
  chain.single = vi.fn(singleResult);
  return chain;
}

let mockSingle: () => Promise<{ data: unknown; error: unknown }>;

// Default: config found
mockSingle = vi.fn().mockResolvedValue({
  data: {
    id: 'cfg-1',
    account_id: 'acct-1',
    instance_url: 'https://magneto-dev-ed.my.salesforce.com',
    is_sandbox: true,
    client_id: 'encrypted-client-id',
    client_secret: 'encrypted-client-secret',
    username: 'encrypted-user',
    password: 'encrypted-pass',
    security_token: 'encrypted-token',
    connected_at: '2026-07-30T12:00:00Z',
  },
  error: null,
});

const mockSupabase = mockSupabaseChain(() => mockSingle());

vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(() => mockSupabase),
}));

vi.mock('@/lib/salesforce/client', () => ({
  SalesforceClient: vi.fn(function (
    this: { config: Record<string, unknown> },
    encryptedConfig: Record<string, unknown>,
  ) {
    this.config = encryptedConfig;
  }),
}));

vi.mock('@/lib/audit', () => ({
  recordAuditEvent: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const MOCK_CASE: SalesforceCase = {
  Id: '5005g00001ABCDEFGHI',
  CaseNumber: '00001001',
  Status: 'New',
  Subject: 'Help request',
  Description: 'Customer needs assistance',
  ContactId: '0035g00001ABCDEFGHI',
  CreatedDate: '2026-07-30T14:00:00.000+0000',
};

const MOCK_FEED_ITEM: SalesforceFeedItem = {
  Id: '0D55g00001ABCDEFGHI',
  Body: 'This is a note',
  CreatedDate: '2026-07-30T14:05:00.000+0000',
  CreatedBy: { Name: 'Admin User' },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Salesforce Sync Triggers', () => {
  let createCaseMock: ReturnType<typeof vi.fn>;
  let updateCaseMock: ReturnType<typeof vi.fn>;
  let postFeedItemMock: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    vi.clearAllMocks();

    // Reset default chain for config lookups
    mockSingle = vi.fn().mockResolvedValue({
      data: {
        id: 'cfg-1',
        account_id: 'acct-1',
        instance_url: 'https://magneto-dev-ed.my.salesforce.com',
        is_sandbox: true,
        client_id: 'encrypted-client-id',
        client_secret: 'encrypted-client-secret',
        username: 'encrypted-user',
        password: 'encrypted-pass',
        security_token: 'encrypted-token',
        connected_at: '2026-07-30T12:00:00Z',
      },
      error: null,
    });
    // Rebuild the chain so it uses the new mockSingle
    Object.assign(mockSupabase, mockSupabaseChain(() => mockSingle()));

    // Setup mock methods on SalesforceClient prototype
    createCaseMock = vi.fn().mockResolvedValue(MOCK_CASE);
    updateCaseMock = vi.fn().mockResolvedValue(undefined);
    postFeedItemMock = vi.fn().mockResolvedValue(MOCK_FEED_ITEM);

    const { SalesforceClient } = await import('@/lib/salesforce/client');
    SalesforceClient.prototype.createCase = createCaseMock;
    SalesforceClient.prototype.updateCase = updateCaseMock;
    SalesforceClient.prototype.postFeedItem = postFeedItemMock;
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  // ── getSalesforceClient ──────────────────────────────────────

  describe('getSalesforceClient', () => {
    it('returns a SalesforceClient when config exists for the account', async () => {
      const { getSalesforceClient } = await import('./sync');

      const client = await getSalesforceClient('acct-1');

      expect(client).not.toBeNull();
      expect(mockSupabase.from).toHaveBeenCalledWith('salesforce_config');
      expect(mockSupabase.select).toHaveBeenCalledWith('*');
      expect(mockSupabase.eq).toHaveBeenCalledWith('account_id', 'acct-1');
    });

    it('returns null when no config exists for the account', async () => {
      // Override single to return no data
      mockSingle = vi.fn().mockResolvedValue({
        data: null,
        error: { message: 'not found', code: 'PGRST116' },
      });
      Object.assign(mockSupabase, mockSupabaseChain(() => mockSingle()));

      const { getSalesforceClient } = await import('./sync');

      const client = await getSalesforceClient('acct-unknown');
      expect(client).toBeNull();
    });
  });

  // ── escalateToSalesforce ─────────────────────────────────────

  describe('escalateToSalesforce', () => {
    it('creates a Case, mapping row, updates status, and logs audit', async () => {
      // Override from to return different chains per table:
      // - salesforce_config → config
      // - salesforce_case_mappings → success insert
      // - conversations → update success
      const configChain = mockSupabaseChain(() =>
        Promise.resolve({
          data: {
            id: 'cfg-1',
            account_id: 'acct-1',
            instance_url: 'https://magneto-dev-ed.my.salesforce.com',
            is_sandbox: true,
            client_id: 'encrypted-client-id',
            client_secret: 'encrypted-client-secret',
            username: 'encrypted-user',
            password: 'encrypted-pass',
            security_token: 'encrypted-token',
            connected_at: '2026-07-30T12:00:00Z',
          },
          error: null,
        }),
      );

      const mappingInsert = vi.fn().mockResolvedValue({ error: null });
      const mappingChain = {
        insert: mappingInsert,
      };

      const convEq = vi.fn().mockResolvedValue({ error: null });
      const convUpdate = vi.fn(() => ({ eq: convEq }));
      const convChain = {
        update: convUpdate,
      };

      mockSupabase.from = vi.fn((table: string) => {
        if (table === 'salesforce_config') return configChain;
        if (table === 'salesforce_case_mappings') return mappingChain;
        if (table === 'conversations') return convChain;
        return configChain;
      });

      const { escalateToSalesforce } = await import('./sync');

      const result = await escalateToSalesforce(
        'acct-1',
        'conv-1',
        'Help request',
        'Customer needs assistance',
        '0035g00001ABCDEFGHI',
      );

      // Verify case was created with correct params
      expect(createCaseMock).toHaveBeenCalledWith({
        subject: 'Help request',
        description: 'Customer needs assistance',
        contactId: '0035g00001ABCDEFGHI',
        origin: 'WhatsApp',
      });

      // Verify mapping was inserted
      expect(mappingInsert).toHaveBeenCalledWith({
        account_id: 'acct-1',
        conversation_id: 'conv-1',
        salesforce_case_id: MOCK_CASE.Id,
        salesforce_case_number: MOCK_CASE.CaseNumber,
        direction: 'outbound',
        escalation_status: 'escalated',
        last_sync_status: 'synced',
        last_synced_at: expect.any(String),
      });

      // Verify conversation status updated
      expect(convUpdate).toHaveBeenCalledWith({ status: 'waiting' });
      expect(convEq).toHaveBeenCalledWith('id', 'conv-1');

      // Verify audit event recorded
      const { recordAuditEvent } = await import('@/lib/audit');
      expect(recordAuditEvent).toHaveBeenCalledWith({
        accountId: 'acct-1',
        userId: 'system',
        action: 'salesforce.escalated',
        targetType: 'conversation',
        targetId: 'conv-1',
        newValues: {
          salesforceCaseId: MOCK_CASE.Id,
          caseNumber: MOCK_CASE.CaseNumber,
        },
      });

      // Verify return value
      expect(result).toEqual({
        caseId: MOCK_CASE.Id,
        caseNumber: MOCK_CASE.CaseNumber,
      });
    });

    it('throws when Salesforce is not configured', async () => {
      // Override single to return no config
      mockSingle = vi.fn().mockResolvedValue({
        data: null,
        error: { message: 'not found', code: 'PGRST116' },
      });
      Object.assign(mockSupabase, mockSupabaseChain(() => mockSingle()));

      const { escalateToSalesforce } = await import('./sync');

      await expect(
        escalateToSalesforce('acct-unknown', 'conv-1', 'Test'),
      ).rejects.toThrow('Salesforce not configured');
    });
  });

  // ── syncNoteToSalesforce ─────────────────────────────────────

  describe('syncNoteToSalesforce', () => {
    it('posts a FeedItem when a mapping exists', async () => {
      // Override from to return different chains:
      // - salesforce_case_mappings → found
      // - salesforce_config → found
      const mappingChain = mockSupabaseChain(() =>
        Promise.resolve({
          data: { salesforce_case_id: '5005g00001ABCDEFGHI' },
          error: null,
        }),
      );

      mockSupabase.from = vi.fn((table: string) => {
        if (table === 'salesforce_case_mappings') return mappingChain;
        // salesforce_config stays default via configChain
        return mockSupabaseChain(() =>
          Promise.resolve({
            data: {
              id: 'cfg-1',
              account_id: 'acct-1',
              instance_url: 'https://magneto-dev-ed.my.salesforce.com',
              is_sandbox: true,
              client_id: 'encrypted-client-id',
              client_secret: 'encrypted-client-secret',
              username: 'encrypted-user',
              password: 'encrypted-pass',
              security_token: 'encrypted-token',
              connected_at: '2026-07-30T12:00:00Z',
            },
            error: null,
          }),
        );
      });

      const { syncNoteToSalesforce } = await import('./sync');

      await syncNoteToSalesforce('acct-1', 'conv-1', 'This is a note');

      expect(postFeedItemMock).toHaveBeenCalledWith(
        '5005g00001ABCDEFGHI',
        'This is a note',
      );
    });

    it('does nothing when no mapping exists for the conversation', async () => {
      // Override from for salesforce_case_mappings → empty
      const emptyMappingChain = mockSupabaseChain(() =>
        Promise.resolve({
          data: null,
          error: { message: 'not found', code: 'PGRST116' },
        }),
      );

      mockSupabase.from = vi.fn((table: string) => {
        if (table === 'salesforce_case_mappings') return emptyMappingChain;
        return mockSupabaseChain(() =>
          Promise.resolve({ data: {}, error: null }),
        );
      });

      const { syncNoteToSalesforce } = await import('./sync');

      // Should not throw — silently skip unmapped conversations
      await expect(
        syncNoteToSalesforce('acct-1', 'conv-1', 'This is a note'),
      ).resolves.toBeUndefined();

      expect(postFeedItemMock).not.toHaveBeenCalled();
    });
  });

  // ── syncStatusToSalesforce ───────────────────────────────────

  describe('syncStatusToSalesforce', () => {
    function statusMappingChain() {
      return mockSupabaseChain(() =>
        Promise.resolve({
          data: { salesforce_case_id: '5005g00001ABCDEFGHI' },
          error: null,
        }),
      );
    }

    function configChain() {
      return mockSupabaseChain(() =>
        Promise.resolve({
          data: {
            id: 'cfg-1',
            account_id: 'acct-1',
            instance_url: 'https://magneto-dev-ed.my.salesforce.com',
            is_sandbox: true,
            client_id: 'encrypted-client-id',
            client_secret: 'encrypted-client-secret',
            username: 'encrypted-user',
            password: 'encrypted-pass',
            security_token: 'encrypted-token',
            connected_at: '2026-07-30T12:00:00Z',
          },
          error: null,
        }),
      );
    }

    function setupStatusMock(fromFn: (table: string) => unknown) {
      mockSupabase.from = vi.fn(fromFn);
    }

    it('maps "closed" to Salesforce "Closed" status', async () => {
      setupStatusMock((table: string) => {
        if (table === 'salesforce_case_mappings') return statusMappingChain();
        return configChain();
      });

      const { syncStatusToSalesforce } = await import('./sync');
      await syncStatusToSalesforce('acct-1', 'conv-1', 'closed');

      expect(updateCaseMock).toHaveBeenCalledWith('5005g00001ABCDEFGHI', {
        Status: 'Closed',
      });
    });

    it('maps "waiting" to Salesforce "Waiting on Customer" status', async () => {
      setupStatusMock((table: string) => {
        if (table === 'salesforce_case_mappings') return statusMappingChain();
        return configChain();
      });

      const { syncStatusToSalesforce } = await import('./sync');
      await syncStatusToSalesforce('acct-1', 'conv-1', 'waiting');

      expect(updateCaseMock).toHaveBeenCalledWith('5005g00001ABCDEFGHI', {
        Status: 'Waiting on Customer',
      });
    });

    it('maps any other status to "In Progress"', async () => {
      setupStatusMock((table: string) => {
        if (table === 'salesforce_case_mappings') return statusMappingChain();
        return configChain();
      });

      const { syncStatusToSalesforce } = await import('./sync');
      await syncStatusToSalesforce('acct-1', 'conv-1', 'active');

      expect(updateCaseMock).toHaveBeenCalledWith('5005g00001ABCDEFGHI', {
        Status: 'In Progress',
      });
    });

    it('does nothing when no mapping exists', async () => {
      const emptyMappingChain = mockSupabaseChain(() =>
        Promise.resolve({
          data: null,
          error: { message: 'not found', code: 'PGRST116' },
        }),
      );

      mockSupabase.from = vi.fn((table: string) => {
        if (table === 'salesforce_case_mappings') return emptyMappingChain;
        return configChain();
      });

      const { syncStatusToSalesforce } = await import('./sync');

      await expect(
        syncStatusToSalesforce('acct-1', 'conv-1', 'closed'),
      ).resolves.toBeUndefined();

      expect(updateCaseMock).not.toHaveBeenCalled();
    });
  });
});
