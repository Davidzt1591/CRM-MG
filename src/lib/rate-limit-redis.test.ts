import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { __resetRateLimitForTests } from './rate-limit';
import { checkRateLimitWithRedis } from './rate-limit';

const OPTS = { limit: 3, windowMs: 60_000 };

// ---------------------------------------------------------------------------
// The in-memory `checkRateLimit` behaviour is tested in rate-limit.test.ts.
// Here we cover the Redis-specific contract:
// 1. When UPSTASH env vars are set, delegates to Upstash REST.
// 2. When absent, falls back to in-memory transparently.
// 3. On Redis error (network/auth/parse), degrades to in-memory so an
//    Upstash outage never blocks requests.
// ---------------------------------------------------------------------------

/**
 * Minimal mock that simulates the Upstash REST JSON response.
 * The Upstash API returns `{ result: "..." }`.
 */
function mockUpstashOk(result: string) {
  vi.mocked(fetch).mockResolvedValue({
    ok: true,
    status: 200,
    json: () => Promise.resolve({ result }),
  } as Response);
}

beforeEach(() => {
  vi.stubEnv('UPSTASH_REDIS_REST_URL', 'https://eu1-test-12345.upstash.io');
  vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', 'mock-token');
  __resetRateLimitForTests();
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe('checkRateLimitWithRedis', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch');
  });

  it('permits the first request and decrements remaining (Redis)', async () => {
    // INCR returns 1 for the first request.
    mockUpstashOk('1');

    const result = await checkRateLimitWithRedis('user:r1', OPTS);
    expect(result).toMatchObject({
      success: true,
      remaining: 2,
      limit: 3,
    });
    expect(result.reset).toBeGreaterThan(Date.now());

    // Should have called INCR, and then EXPIRE (since count === 1).
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/INCR/'),
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer mock-token',
        }),
      }),
    );
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/EXPIRE/'),
      expect.any(Object),
    );
  });

  it('rejects when count exceeds limit (Redis)', async () => {
    // INCR returns 4 — the counter is already past the limit of 3.
    mockUpstashOk('4');

    const result = await checkRateLimitWithRedis('user:r-over', OPTS);
    expect(result.success).toBe(false);
    expect(result.remaining).toBe(0);
    // Should NOT call EXPIRE — only INCR.
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('falls back to in-memory when UPSTASH_REDIS_REST_URL is not set', async () => {
    vi.stubEnv('UPSTASH_REDIS_REST_URL', '');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', '');

    const result = await checkRateLimitWithRedis('user:no-redis', OPTS);
    expect(result.success).toBe(true);
    expect(result.remaining).toBe(2);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('falls back to in-memory when Upstash returns a non-ok status', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 401,
      json: () => Promise.resolve({ error: 'Unauthorized' }),
    } as Response);

    const result = await checkRateLimitWithRedis('user:unauth', OPTS);
    expect(result.success).toBe(true);
    expect(result.remaining).toBe(2);
  });

  it('falls back to in-memory when fetch throws (network error)', async () => {
    vi.mocked(fetch).mockRejectedValue(new Error('ECONNREFUSED'));

    const result = await checkRateLimitWithRedis('user:err', OPTS);
    expect(result.success).toBe(true);
    expect(result.remaining).toBe(2);
  });

  it('falls back to in-memory when Upstash response body is unparseable', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.reject(new Error('Unexpected token')),
    } as Response);

    const result = await checkRateLimitWithRedis('user:bad-json', OPTS);
    expect(result.success).toBe(true);
    expect(result.remaining).toBe(2);
  });
});
