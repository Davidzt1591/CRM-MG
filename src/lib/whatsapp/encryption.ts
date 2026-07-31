import crypto from 'crypto'

/**
 * WhatsApp token encryption.
 *
 * Format — GCM (current):
 *   `<iv-hex>:<ciphertext-hex>:<authTag-hex>`      (three colons)
 *
 * Format — CBC (legacy, decrypt-only):
 *   `<iv-hex>:<ciphertext-hex>`                    (one colon)
 *
 * Why GCM instead of CBC:
 *   CBC without a MAC is unauthenticated — an attacker who can write
 *   rows to `whatsapp_config` (directly, through a future RLS bug, or
 *   via a DB backup being modified) can flip bits in the ciphertext
 *   without the decrypt throwing. You'd silently get garbled tokens;
 *   worst case, if the mutated bytes happen to form a valid access
 *   token, messages go out under a spoofed account. GCM appends a
 *   16-byte authentication tag; any tampering fails the decrypt hard.
 *
 * Backward compatibility:
 *   `decrypt()` auto-detects the format by counting parts, so legacy
 *   rows keep working. New `encrypt()` output is always GCM.
 *   Existing rows can be upgraded in place by call sites that hold a
 *   Supabase client — see the `isLegacyFormat` / `encrypt` pattern in
 *   `src/app/api/whatsapp/send/route.ts`.
 *
 * Key rotation:
 *   Set `ENCRYPTION_KEY_PREVIOUS` to the old key (32-byte hex) before
 *   deploying the new `ENCRYPTION_KEY`. `decrypt()` tries the current
 *   key first, then the previous key as fallback. Call `reEncrypt()`
 *   on any value that was decrypted with the previous key to rewrite it
 *   with the current key — this lets you rotate keys without a data
 *   migration window.
 */

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY!
const ENCRYPTION_KEY_PREVIOUS = process.env.ENCRYPTION_KEY_PREVIOUS
// 12 bytes is the NIST-recommended IV length for GCM — keeps the
// counter block well below 2^32 and matches the default web-crypto
// behaviour, so any future port is straightforward.
const GCM_IV_LENGTH = 12
const CBC_IV_LENGTH = 16
const AUTH_TAG_LENGTH = 16

/**
 * Encrypt plaintext with AES-256-GCM using the current ENCRYPTION_KEY.
 */
export function encrypt(text: string): string {
  const iv = crypto.randomBytes(GCM_IV_LENGTH)
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    Buffer.from(ENCRYPTION_KEY, 'hex'),
    iv,
  )
  let encrypted = cipher.update(text, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  const authTag = cipher.getAuthTag()
  return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`
}

// ---------------------------------------------------------------------------
// Internal: decrypt with an explicit key. Shared by the public decrypt()
// (which tries current + fallback) and reEncrypt().
// ---------------------------------------------------------------------------

function decryptWithKey(encryptedText: string, keyHex: string): string {
  const parts = encryptedText.split(':')

  if (parts.length === 3) {
    // GCM — current format.
    const [ivHex, ctHex, tagHex] = parts
    const iv = Buffer.from(ivHex, 'hex')
    if (iv.length !== GCM_IV_LENGTH) {
      throw new Error(
        `Encrypted token has unexpected GCM IV length ${iv.length}`,
      )
    }
    const authTag = Buffer.from(tagHex, 'hex')
    if (authTag.length !== AUTH_TAG_LENGTH) {
      throw new Error(
        `Encrypted token has unexpected GCM auth-tag length ${authTag.length}`,
      )
    }
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      Buffer.from(keyHex, 'hex'),
      iv,
    )
    decipher.setAuthTag(authTag)
    let decrypted = decipher.update(ctHex, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  }

  if (parts.length === 2) {
    // CBC — legacy. Read-only; `encrypt()` never produces this shape.
    const [ivHex, ctHex] = parts
    const iv = Buffer.from(ivHex, 'hex')
    if (iv.length !== CBC_IV_LENGTH) {
      throw new Error(
        `Encrypted token has unexpected CBC IV length ${iv.length}`,
      )
    }
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      Buffer.from(keyHex, 'hex'),
      iv,
    )
    let decrypted = decipher.update(ctHex, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  }

  throw new Error(
    `Encrypted token has unrecognised format (expected 1 or 2 colons, got ${
      parts.length - 1
    })`,
  )
}

/**
 * Decrypt a ciphertext using the current key.
 * Falls back to ENCRYPTION_KEY_PREVIOUS when the current key fails
 * (e.g. the ciphertext was created before a key rotation).
 */
export function decrypt(encryptedText: string): string {
  try {
    return decryptWithKey(encryptedText, ENCRYPTION_KEY)
  } catch (e) {
    // If a previous key is configured, try it as fallback.
    if (ENCRYPTION_KEY_PREVIOUS) {
      return decryptWithKey(encryptedText, ENCRYPTION_KEY_PREVIOUS)
    }
    // No fallback — rethrow the original error (auth tag mismatch,
    // unrecognised format, etc.).
    throw e
  }
}

/**
 * Re-encrypt a ciphertext with the current key.
 *
 * Tries the current key first, then ENCRYPTION_KEY_PREVIOUS as fallback
 * (same as `decrypt()`). Re-encrypts with the current key.
 *
 * Use this during a key rotation to upgrade stored ciphertexts without
 * a data migration: read each row, call `reEncrypt()`, write the result
 * back. Entries already using the current key are re-encrypted in-place
 * (produces a fresh IV, same plaintext).
 */
export function reEncrypt(encryptedText: string): string {
  try {
    return encrypt(decryptWithKey(encryptedText, ENCRYPTION_KEY))
  } catch (e) {
    if (ENCRYPTION_KEY_PREVIOUS) {
      return encrypt(decryptWithKey(encryptedText, ENCRYPTION_KEY_PREVIOUS))
    }
    throw e
  }
}

/**
 * Cheap format detector — call sites use this to decide whether to
 * write a refreshed GCM ciphertext back to the database after a
 * successful legacy decrypt. Does not attempt decryption; purely a
 * structural check.
 */
export function isLegacyFormat(encryptedText: string): boolean {
  return encryptedText.split(':').length === 2
}
