import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { createHmac } from 'node:crypto';
import { verifySalesforceWebhook } from './webhook';

// ---------------------------------------------------------------------------
// Mutable mock — vitest hoisting requires these at top level.
// The object is mutated in beforeEach so cached module references still work.
// ---------------------------------------------------------------------------

function makeChain(singleResult?: () => Promise<{ data: unknown; error: unknown }>) {
  const chain: Record<string, unknown> = {};
  const methods = ['from', 'select', 'insert', 'update', 'eq', 'order', 'limit'] as const;
  for (const m of methods) {
    chain[m] = vi.fn(() => chain);
  }
  chain.single = vi.fn(singleResult ?? (() => Promise.resolve({ data: null, error: null })));
  chain.maybeSingle = vi.fn(singleResult ?? (() => Promise.resolve({ data: null, error: null })));
  return chain;
}

// Shared mutable mock object — we mutate its `.from` property in beforeEach.
const mockSupabase = { from: vi.fn() } as Record<string, unknown>;

// Reassign methods inside mockSupabase without replacing the object itself.
function setFrom(fn: (table: string) => unknown) {
  mockSupabase.from = vi.fn(fn);
}

vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(() => mockSupabase),
}));

vi.mock('@/lib/audit', () => ({
  recordAuditEvent: vi.fn(),
}));

// ---------------------------------------------------------------------------
// verifySalesforceWebhook — pure function, no mocks needed
// ---------------------------------------------------------------------------

describe('verifySalesforceWebhook', () => {
  const secret = 'whsec_test_secret_123';
  const body = JSON.stringify({
    event: 'test',
    data: { caseId: '5005g00001ABCDEFGHI' },
  });

  function sign(s: string, b: string): string {
    return createHmac('sha256', s).update(b).digest('base64');
  }

  it('returns true for a valid signature', () => {
    const sig = sign(secret, body);
    expect(verifySalesforceWebhook(sig, body, secret)).toBe(true);
  });

  it('returns false when the signature does not match the body', () => {
    expect(
      verifySalesforceWebhook('aW52YWxpZF9zaWduYXR1cmU=', body, secret),
    ).toBe(false);
  });

  it('returns false when signed with a different secret', () => {
    const sig = sign('wrong-secret', body);
    expect(verifySalesforceWebhook(sig, body, secret)).toBe(false);
  });

  it('returns false when the provided secret is empty', () => {
    const sig = sign('', body);
    expect(verifySalesforceWebhook(sig, body, '')).toBe(false);
  });

  it('returns false when the signature header is empty', () => {
    expect(verifySalesforceWebhook('', body, secret)).toBe(false);
  });

  it('returns false when signature length differs from expected (timingSafeEqual guard)', () => {
    const sig = sign(secret, body);
    expect(verifySalesforceWebhook(sig + 'extra', body, secret)).toBe(false);
  });

  it('returns false when signature is shorter than expected', () => {
    const sig = sign(secret, body);
    expect(verifySalesforceWebhook(sig.slice(0, 4), body, secret)).toBe(false);
  });

  it('returns false when signature header is null', () => {
    expect(
      verifySalesforceWebhook(null as unknown as string, body, secret),
    ).toBe(false);
  });

  it('handles empty body gracefully', () => {
    const sig = sign(secret, '');
    expect(verifySalesforceWebhook(sig, '', secret)).toBe(true);
  });

  it('handles non-ASCII body content', () => {
    const nonAscii = JSON.stringify({ msg: 'ññoño' });
    const sig = sign(secret, nonAscii);
    expect(verifySalesforceWebhook(sig, nonAscii, secret)).toBe(true);
  });

  it('is timing-safe — different content with same length returns false', () => {
    const bodyA = JSON.stringify({ a: 1, b: 2 });
    const bodyB = JSON.stringify({ a: 2, b: 1 });
    const sigA = sign(secret, bodyA);
    expect(verifySalesforceWebhook(sigA, bodyB, secret)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// processSalesforceCDC
// ---------------------------------------------------------------------------

describe('processSalesforceCDC', () => {
  const mockConfig = {
    accountId: 'acct-1',
    instanceUrl: 'https://magneto-dev-ed.my.salesforce.com',
    secret: 'whsec_test',
  };

  beforeEach(() => {
    // Reset from to default: any table → makeChain
    setFrom(() => makeChain());
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('does nothing when CDC payload has no ChangeEventHeader', async () => {
    const { processSalesforceCDC } = await import('./webhook');
    await expect(
      processSalesforceCDC(mockConfig, { SomeField: 'value' }),
    ).resolves.toBeUndefined();
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });

  it('processes a status-change CDC event and updates the mapping', async () => {
    const chain = makeChain(() =>
      Promise.resolve({
        data: {
          id: 'map-1',
          conversation_id: 'conv-1',
          salesforce_case_id: '5005g00001ABCDEFGHI',
          escalation_status: 'active',
        },
        error: null,
      }),
    );

    // All tables return the same chain
    setFrom(() => chain);

    const { processSalesforceCDC } = await import('./webhook');

    const cdcPayload = {
      ChangeEventHeader: {
        entityName: 'Case',
        recordIds: ['5005g00001ABCDEFGHI'],
        changeType: 'UPDATE',
        changedFields: ['Status', 'LastModifiedDate'],
      },
      Status: 'Waiting on Customer',
    };

    await processSalesforceCDC(mockConfig, cdcPayload);

    expect(mockSupabase.from).toHaveBeenCalledWith('salesforce_case_mappings');
    expect(chain.select).toHaveBeenCalledWith('*');
    expect(chain.eq).toHaveBeenCalledWith(
      'salesforce_case_id',
      '5005g00001ABCDEFGHI',
    );
    expect(chain.update).toHaveBeenCalledWith(
      expect.objectContaining({ escalation_status: 'waiting' }),
    );
  });

  it('skips gracefully when no mapping exists for the CDC event', async () => {
    const chain = makeChain(() =>
      Promise.resolve({
        data: null,
        error: { message: 'not found', code: 'PGRST116' },
      }),
    );

    setFrom(() => chain);

    const { processSalesforceCDC } = await import('./webhook');

    await expect(
      processSalesforceCDC(mockConfig, {
        ChangeEventHeader: {
          entityName: 'Case',
          recordIds: ['5005g00001UNKNOWN'],
          changeType: 'UPDATE',
          changedFields: ['Status'],
        },
        Status: 'Closed',
      }),
    ).resolves.toBeUndefined();
  });

  it('maps Salesforce "Closed" status to escalation_status resolved and conversation closed', async () => {
    const chain = makeChain(() =>
      Promise.resolve({
        data: {
          id: 'map-2',
          conversation_id: 'conv-2',
          salesforce_case_id: '5005g00002ABCDEFGHI',
          escalation_status: 'active',
        },
        error: null,
      }),
    );

    setFrom(() => chain);

    const { processSalesforceCDC } = await import('./webhook');

    await processSalesforceCDC(mockConfig, {
      ChangeEventHeader: {
        entityName: 'Case',
        recordIds: ['5005g00002ABCDEFGHI'],
        changeType: 'UPDATE',
        changedFields: ['Status'],
      },
      Status: 'Closed',
    });

    expect(chain.update).toHaveBeenCalledWith(
      expect.objectContaining({ escalation_status: 'resolved' }),
    );
    expect(chain.update).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'closed' }),
    );
  });

  it('adds a system message when status changes', async () => {
    const chain = makeChain(() =>
      Promise.resolve({
        data: {
          id: 'map-3',
          conversation_id: 'conv-3',
          salesforce_case_id: '5005g00003ABCDEFGHI',
          escalation_status: 'waiting',
        },
        error: null,
      }),
    );

    setFrom(() => chain);

    const { processSalesforceCDC } = await import('./webhook');

    await processSalesforceCDC(mockConfig, {
      ChangeEventHeader: {
        entityName: 'Case',
        recordIds: ['5005g00003ABCDEFGHI'],
        changeType: 'UPDATE',
        changedFields: ['Status'],
      },
      Status: 'Working',
    });

    expect(chain.insert).toHaveBeenCalledWith(
      expect.objectContaining({
        conversation_id: 'conv-3',
        sender_type: 'system',
      }),
    );
  });

  it('records an audit event for CDC processing', async () => {
    const chain = makeChain(() =>
      Promise.resolve({
        data: {
          id: 'map-4',
          conversation_id: 'conv-4',
          salesforce_case_id: '5005g00004ABCDEFGHI',
          escalation_status: 'active',
        },
        error: null,
      }),
    );

    setFrom(() => chain);

    const { processSalesforceCDC } = await import('./webhook');
    const { recordAuditEvent } = await import('@/lib/audit');

    await processSalesforceCDC(mockConfig, {
      ChangeEventHeader: {
        entityName: 'Case',
        recordIds: ['5005g00004ABCDEFGHI'],
        changeType: 'UPDATE',
        changedFields: ['Status'],
      },
      Status: 'In Progress',
    });

    expect(recordAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        accountId: 'acct-1',
        action: 'salesforce.cdc_received',
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// processSalesforceCaseUpdate
// ---------------------------------------------------------------------------

describe('processSalesforceCaseUpdate', () => {
  const mockConfig = {
    accountId: 'acct-1',
    instanceUrl: 'https://magneto-dev-ed.my.salesforce.com',
    secret: 'whsec_test',
  };

  beforeEach(() => {
    setFrom(() => makeChain());
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('updates conversation status when status changes', async () => {
    const chain = makeChain(() =>
      Promise.resolve({
        data: {
          id: 'map-1',
          conversation_id: 'conv-1',
          escalation_status: 'active',
        },
        error: null,
      }),
    );

    setFrom(() => chain);

    const { processSalesforceCaseUpdate } = await import('./webhook');

    await processSalesforceCaseUpdate(mockConfig, '5005g00001ABCDEFGHI', {
      Status: 'Waiting on Customer',
    });

    expect(mockSupabase.from).toHaveBeenCalledWith('salesforce_case_mappings');
    expect(chain.eq).toHaveBeenCalledWith(
      'salesforce_case_id',
      '5005g00001ABCDEFGHI',
    );
    expect(chain.update).toHaveBeenCalled();
  });

  it('does nothing when no mapping exists', async () => {
    const chain = makeChain(() =>
      Promise.resolve({
        data: null,
        error: { message: 'not found', code: 'PGRST116' },
      }),
    );

    setFrom(() => chain);

    const { processSalesforceCaseUpdate } = await import('./webhook');

    await expect(
      processSalesforceCaseUpdate(mockConfig, '5005g00001UNKNOWN', {
        Status: 'Closed',
      }),
    ).resolves.toBeUndefined();

    expect(chain.update).not.toHaveBeenCalled();
  });

  it('maps "Waiting on Customer" to waiting status', async () => {
    const chain = makeChain(() =>
      Promise.resolve({
        data: {
          id: 'map-2',
          conversation_id: 'conv-2',
          escalation_status: 'escalated',
        },
        error: null,
      }),
    );

    setFrom(() => chain);

    const { processSalesforceCaseUpdate } = await import('./webhook');

    await processSalesforceCaseUpdate(mockConfig, '5005g00002ABCDEFGHI', {
      Status: 'Waiting on Customer',
    });

    expect(chain.update).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'waiting' }),
    );
  });
});
