/**
 * Passphrase protection for client (secret) keys, with WebCrypto only.
 *
 * The key is encrypted with AES-256-GCM under a key derived from the passphrase
 * with PBKDF2-HMAC-SHA256 (600,000 iterations, OWASP's 2023 recommendation; the
 * Web Crypto API offers no memory-hard KDF). The SHA-256 of the matching server
 * key is authenticated as additional data, so a sealed key only opens for the
 * server key it belongs to and cannot be swapped onto another one.
 *
 * Runs in the TFHE worker, so the plaintext key never reaches the page.
 */

import { base64ToBytes, bytesToBase64 } from './encoding.js';

export const KDF_ITERATIONS = 600_000;
/** Bounds for keys read back (e.g. from an imported file). */
const MIN_ITERATIONS = 1_000;
const MAX_ITERATIONS = 10_000_000;
export const PASSPHRASE_MIN_LENGTH = 10;

export interface SealedKey {
  v: 1;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  /** base64 */
  salt: string;
  /** base64 */
  iv: string;
  /** base64; AES-GCM ciphertext with its 16-byte tag appended */
  ciphertext: string;
}

export class WrongPassphraseError extends Error {
  constructor() {
    super('Wrong passphrase');
    this.name = 'WrongPassphraseError';
  }
}

const encoder = new TextEncoder();

function additionalData(serverKeySha256: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(`heaas-client-key/v1\0${serverKeySha256}`);
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase.normalize('NFC')),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function seal(
  secret: Uint8Array<ArrayBuffer>,
  passphrase: string,
  serverKeySha256: string,
  iterations = KDF_ITERATIONS
): Promise<SealedKey> {
  if (passphrase.length < PASSPHRASE_MIN_LENGTH) {
    throw new RangeError(`The passphrase needs at least ${PASSPHRASE_MIN_LENGTH} characters`);
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, iterations);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: additionalData(serverKeySha256) },
    key,
    secret
  );
  return {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iterations,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
}

export function isSealedKey(value: unknown): value is SealedKey {
  const v = value as Partial<SealedKey> | null;
  return (
    typeof v === 'object' &&
    v !== null &&
    v.v === 1 &&
    v.kdf === 'PBKDF2-SHA256' &&
    Number.isInteger(v.iterations) &&
    (v.iterations ?? 0) >= MIN_ITERATIONS &&
    (v.iterations ?? 0) <= MAX_ITERATIONS &&
    typeof v.salt === 'string' &&
    typeof v.iv === 'string' &&
    typeof v.ciphertext === 'string'
  );
}

/** Decrypts a sealed key; throws `WrongPassphraseError` if it does not open. */
export async function open(
  sealed: SealedKey,
  passphrase: string,
  serverKeySha256: string
): Promise<Uint8Array<ArrayBuffer>> {
  if (!isSealedKey(sealed)) throw new Error('Not a protected HEaaS key');
  const key = await deriveKey(passphrase, base64ToBytes(sealed.salt), sealed.iterations);
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64ToBytes(sealed.iv),
        additionalData: additionalData(serverKeySha256)
      },
      key,
      base64ToBytes(sealed.ciphertext)
    );
    return new Uint8Array(plaintext);
  } catch {
    // GCM cannot tell a wrong passphrase from a key sealed for another server key.
    throw new WrongPassphraseError();
  }
}

/** Lower-case hex SHA-256, as the server reports it for uploaded keys. */
export async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}
