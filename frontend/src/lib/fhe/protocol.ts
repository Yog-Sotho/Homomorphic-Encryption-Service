/**
 * Messages exchanged between the main thread and the TFHE Web Worker.
 *
 * All TFHE work (key generation, encryption, decryption) and all handling of
 * plaintext client keys runs in the worker: the page only ever sees the client
 * key sealed under the user's passphrase. Byte arrays are transferred, not copied.
 */

import type { SealedKey } from './vault.js';

/** Size limits passed to TFHE's safe (de)serialization. Mirror the backend's limits. */
export const LIMITS = {
  ciphertextBytes: 1n << 20n,
  clientKeyBytes: 1n << 26n,
  serverKeyBytes: 1n << 30n
} as const;

export type WorkerRequest =
  | { id: number; kind: 'generateKeys'; passphrase: string }
  | { id: number; kind: 'unlock'; sealed: SealedKey; serverKeySha256: string; passphrase: string }
  /** Seals a raw key stored before passphrases existed, and loads it. */
  | { id: number; kind: 'protect'; clientKey: Uint8Array<ArrayBuffer>; serverKeySha256: string; passphrase: string }
  | { id: number; kind: 'lock' }
  | { id: number; kind: 'encrypt'; values: number[] }
  | { id: number; kind: 'decrypt'; ciphertext: Uint8Array<ArrayBuffer> };

export interface GeneratedKeys {
  /** The client key, sealed under the passphrase and bound to the server key. */
  sealed: SealedKey;
  compressedServerKey: Uint8Array<ArrayBuffer>;
  /** Hex SHA-256 of `compressedServerKey`, as the server reports it after upload. */
  serverKeySha256: string;
}

export type WorkerResult =
  | { kind: 'generateKeys'; keys: GeneratedKeys }
  | { kind: 'unlock' }
  | { kind: 'protect'; sealed: SealedKey }
  | { kind: 'lock' }
  | { kind: 'encrypt'; ciphertexts: Uint8Array<ArrayBuffer>[] }
  | { kind: 'decrypt'; value: number };

export type WorkerResponse =
  | { id: number; ok: true; result: WorkerResult }
  | { id: number; ok: false; error: string; wrongPassphrase?: boolean };
