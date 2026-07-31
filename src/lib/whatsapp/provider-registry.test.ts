import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Mock Supabase before importing the module under test.
const mockSingle = vi.fn();
const mockSelect = vi.fn(() => ({
  select: mockSelect,
}));
const mockEq = vi.fn(() => ({
  eq: mockEq,
  single: mockSingle,
}));
const mockFrom = vi.fn(() => ({
  select: () => ({
    ...mockSelect(),
    eq: mockEq,
    single: mockSingle,
  }),
  eq: mockEq,
  single: mockSingle,
}));

const mockSupabaseClient = {
  from: mockFrom,
};

vi.mock('@supabase/supabase-js', () => ({
  createClient: () => mockSupabaseClient,
}));

import { clearProviderCache, getProvider } from './provider-registry';
import { MetaAdapter } from './meta-adapter';

describe('provider-registry', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearProviderCache();

    // Set env vars the registry reads at call time.
    process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
    process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key';
  });

  afterEach(() => {
    delete process.env.NEXT_PUBLIC_SUPABASE_URL;
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    clearProviderCache();
  });

  // ── getProvider — loads from DB on first call ────────────────

  it('loads config from db and returns a MetaAdapter for provider=meta', async () => {
    mockSingle.mockResolvedValueOnce({
      data: {
        provider: 'meta',
        access_token: 'encrypted-meta-token',
        phone_number_id: 'phone-123',
        waba_id: 'waba-456',
        provider_config: {},
      },
      error: null,
    });

    const provider = await getProvider('acct-1');

    expect(mockFrom).toHaveBeenCalledWith('whatsapp_config');
    expect(provider).toBeInstanceOf(MetaAdapter);
    expect(provider.name).toBe('Meta Cloud API');
  });

  // ── getProvider — returns MetaAdapter fallback for openwa (PR #2) ───

  it('returns OpenWAAdapter for provider=openwa', async () => {
    mockSingle.mockResolvedValueOnce({
      data: {
        provider: 'openwa',
        access_token: 'encrypted-openwa-token',
        phone_number_id: 'phone-789',
        waba_id: null,
        provider_config: { apiUrl: 'http://localhost:2785', apiKey: 'key', secret: 'secret' },
      },
      error: null,
    });

    const provider = await getProvider('acct-2');

    expect(provider.constructor.name).toBe('OpenWAAdapter');
    expect(provider.name).toBe('OpenWA');
  });

  // ── getProvider — caching ────────────────────────────────────

  it('caches the provider for 60s and does not re-query the db', async () => {
    mockSingle.mockResolvedValueOnce({
      data: {
        provider: 'meta',
        access_token: 'token',
        phone_number_id: 'phone',
        waba_id: 'waba',
        provider_config: {},
      },
      error: null,
    });

    const p1 = await getProvider('acct-1');
    const p2 = await getProvider('acct-1');

    // Should have only queried once
    expect(mockSingle).toHaveBeenCalledTimes(1);
    expect(p1).toBe(p2); // Same cached instance
  });

  it('re-queries the db after cache expires', async () => {
    vi.useFakeTimers();

    mockSingle.mockResolvedValue({
      data: {
        provider: 'meta',
        access_token: 'token',
        phone_number_id: 'phone',
        waba_id: 'waba',
        provider_config: {},
      },
      error: null,
    });

    await getProvider('acct-1');
    expect(mockSingle).toHaveBeenCalledTimes(1);

    // Advance past 60s TTL
    vi.advanceTimersByTime(61_000);

    await getProvider('acct-1');
    expect(mockSingle).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
  });

  // ── getProvider — error handling ─────────────────────────────

  it('throws when whatsapp_config is not found', async () => {
    mockSingle.mockResolvedValueOnce({
      data: null,
      error: { message: 'Not found' },
    });

    await expect(getProvider('acct-missing')).rejects.toThrow(
      /WhatsApp config not found/
    );
  });

  // ── clearProviderCache ───────────────────────────────────────

  it('clearProviderCache with accountId removes only that entry', async () => {
    mockSingle.mockResolvedValue({
      data: {
        provider: 'meta',
        access_token: 'token',
        phone_number_id: 'phone',
        waba_id: 'waba',
        provider_config: {},
      },
      error: null,
    });

    await getProvider('acct-1');
    await getProvider('acct-2');
    expect(mockSingle).toHaveBeenCalledTimes(2);

    clearProviderCache('acct-1');

    await getProvider('acct-1');
    await getProvider('acct-2');

    // acct-1 re-queried, acct-2 still cached
    expect(mockSingle).toHaveBeenCalledTimes(3);
  });

  it('clearProviderCache without args clears all entries', async () => {
    mockSingle.mockResolvedValue({
      data: {
        provider: 'meta',
        access_token: 'token',
        phone_number_id: 'phone',
        waba_id: 'waba',
        provider_config: {},
      },
      error: null,
    });

    await getProvider('acct-1');
    await getProvider('acct-2');
    expect(mockSingle).toHaveBeenCalledTimes(2);

    clearProviderCache();

    await getProvider('acct-1');
    await getProvider('acct-2');
    expect(mockSingle).toHaveBeenCalledTimes(4); // Both re-queried
  });
});
