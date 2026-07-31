import crypto from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Two distinct 32-byte hex keys to simulate rotation.
const KEY_A = 'a'.repeat(64);
const KEY_B = 'b'.repeat(64);

/**
 * When the module is first loaded, it captures `ENCRYPTION_KEY` as a
 * module-level constant via `process.env.ENCRYPTION_KEY!`.
 * We reset the module cache between setups so each import picks up the
 * current env state.
 */

function module() {
  return import('./encryption');
}

describe('key rotation (reEncrypt)', () => {
  beforeEach(() => {
    process.env.ENCRYPTION_KEY = KEY_A;
    delete process.env.ENCRYPTION_KEY_PREVIOUS;
    vi.resetModules();
  });

  afterEach(() => {
    delete process.env.ENCRYPTION_KEY_PREVIOUS;
  });

  describe('reEncrypt', () => {
    it('re-encrypts data that was encrypted with the current key (identity behaviour)', async () => {
      const { encrypt, decrypt, reEncrypt } = await module();
      const ct = encrypt('token-123');
      const rotated = reEncrypt(ct);
      // Same key — plaintext survives.
      expect(decrypt(rotated)).toBe('token-123');
      // Output is still a valid GCM blob.
      expect(rotated.split(':')).toHaveLength(3);
    });

    it('re-encrypts data that was encrypted with the previous key', async () => {
      // 1. Encrypt with KEY_B (simulating old data).
      process.env.ENCRYPTION_KEY = KEY_B;
      vi.resetModules();
      const modB = await module();
      const oldCt = modB.encrypt('rotated-token');

      // 2. Now switch to KEY_A, with KEY_B as the fallback.
      process.env.ENCRYPTION_KEY = KEY_A;
      process.env.ENCRYPTION_KEY_PREVIOUS = KEY_B;
      vi.resetModules();
      const modCurrent = await module();

      const rotated = modCurrent.reEncrypt(oldCt);
      // Must be decryptable with the CURRENT key only.
      expect(modCurrent.decrypt(rotated)).toBe('rotated-token');
    });

    it('preserves data when the key has not changed', async () => {
      const { encrypt, reEncrypt, decrypt } = await module();
      const ct = encrypt('permanent-token');
      const rotated = reEncrypt(ct);
      expect(decrypt(rotated)).toBe('permanent-token');
    });

    it('throws when neither current nor previous key can decrypt', async () => {
      const { reEncrypt } = await module();
      // Encrypt with a key we don't have.
      const unknownKey = 'c'.repeat(64);
      // Simulate unknown key by bypassing the module.
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(unknownKey, 'hex'), iv);
      let ct = cipher.update('unknown-key-data', 'utf8', 'hex');
      ct += cipher.final('hex');
      const authTag = cipher.getAuthTag();
      const unknownCt = `${iv.toString('hex')}:${ct}:${authTag.toString('hex')}`;

      // Node.js crypto throws "Unsupported state or unable to authenticate data"
      // when AES-GCM auth fails (wrong key, tampered ciphertext).
      expect(() => reEncrypt(unknownCt)).toThrow(/authenticate/i);
    });

    it('throws on an unrecognised ciphertext format', async () => {
      const { reEncrypt } = await module();
      // Single-part blob — no colons.
      expect(() => reEncrypt('not-encrypted-at-all')).toThrow();
      // Four-part blob — too many colons.
      expect(() => reEncrypt('aa:bb:cc:dd')).toThrow();
    });
  });

  describe('transparent fallback (decrypt with previous key)', () => {
    it('decrypts data encrypted with KEY_B when KEY_A is current and KEY_B_PREVIOUS is set', async () => {
      // Encrypt with KEY_B first.
      process.env.ENCRYPTION_KEY = KEY_B;
      vi.resetModules();
      const modB = await module();
      const oldCt = modB.encrypt('fallback-data');

      // Switch to KEY_A + previous KEY_B.
      process.env.ENCRYPTION_KEY = KEY_A;
      process.env.ENCRYPTION_KEY_PREVIOUS = KEY_B;
      vi.resetModules();
      const modCurrent = await module();

      // decrypt should try A → fail → try B → succeed.
      expect(modCurrent.decrypt(oldCt)).toBe('fallback-data');
    });

    it('still fails when no previous key is configured and current key cannot decrypt', async () => {
      process.env.ENCRYPTION_KEY = KEY_B;
      vi.resetModules();
      const modB = await module();
      const oldCt = modB.encrypt('lost-data');

      // Switch to KEY_A with NO previous key.
      process.env.ENCRYPTION_KEY = KEY_A;
      delete process.env.ENCRYPTION_KEY_PREVIOUS;
      vi.resetModules();
      const modCurrent = await module();

      expect(() => modCurrent.decrypt(oldCt)).toThrow();
    });
  });
});
