/**
 * Key backup files: a client key as stored in this browser, sealed under its
 * passphrase. Exporting needs no passphrase (the file is already encrypted);
 * importing needs it, which also proves the file and passphrase belong together.
 */

import { base64ToBytes, bytesToBase64 } from './encoding.js';
import type { ProtectedClientKey } from './keystore.js';
import { isSealedKey, type SealedKey } from './vault.js';

export const KEY_FILE_FORMAT = 'heaas-client-key';
const MAX_KEY_FILE_BYTES = 1 << 20;

export interface KeyFile {
  format: typeof KEY_FILE_FORMAT;
  version: 1;
  /** The server key this client key belongs to. */
  keyId: string;
  serverKeySha256: string;
  createdAt: string;
  sealed: SealedKey;
  /** Base64 compact public key, for proven inputs (absent on older keys). */
  publicKey?: string;
}

export function toKeyFile(record: ProtectedClientKey): string {
  const file: KeyFile = {
    format: KEY_FILE_FORMAT,
    version: 1,
    keyId: record.keyId,
    serverKeySha256: record.serverKeySha256,
    createdAt: record.createdAt,
    sealed: record.sealed
  };
  if (record.publicKey) file.publicKey = bytesToBase64(record.publicKey);
  return JSON.stringify(file, null, 2);
}

/** The public key carried by a key file, if any. */
export function keyFilePublicKey(file: KeyFile): Uint8Array<ArrayBuffer> | undefined {
  return file.publicKey === undefined ? undefined : base64ToBytes(file.publicKey);
}

export function keyFileName(keyId: string): string {
  return `heaas-key-${keyId.slice(0, 8)}.json`;
}

/** Parses and validates a key file; throws an `Error` with a message for the user. */
export function parseKeyFile(text: string): KeyFile {
  const invalid = new Error('This is not a HE Engine key file.');
  if (text.length > MAX_KEY_FILE_BYTES) throw invalid;
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw invalid;
  }
  const file = data as Partial<KeyFile> | null;
  if (typeof file !== 'object' || file === null || file.format !== KEY_FILE_FORMAT) throw invalid;
  if (file.version !== 1) throw new Error('This key file was made by a newer version of HE Engine.');
  const valid =
    typeof file.keyId === 'string' &&
    /^[0-9a-f-]{36}$/i.test(file.keyId) &&
    typeof file.serverKeySha256 === 'string' &&
    /^[0-9a-f]{64}$/.test(file.serverKeySha256) &&
    typeof file.createdAt === 'string' &&
    isSealedKey(file.sealed) &&
    (file.publicKey === undefined ||
      (typeof file.publicKey === 'string' && /^[A-Za-z0-9+/]+={0,2}$/.test(file.publicKey)));
  if (!valid) throw new Error('This key file is damaged.');
  return file as KeyFile;
}
