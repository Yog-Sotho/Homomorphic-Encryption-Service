/**
 * Messages exchanged between the main thread and the TFHE Web Worker.
 *
 * All TFHE work (key generation, encryption, decryption) and all handling of
 * plaintext client keys runs in the worker: the page only ever sees the client
 * key sealed under the user's passphrase. Byte arrays are transferred, not copied.
 */

import type { IntegerType, ValueType } from '../api.js';
import type { SealedKey } from './vault.js';

/** Size limits passed to TFHE's safe (de)serialization. Mirror heaas-core's params.rs. */
export const LIMITS = {
  ciphertextBytes: 1n << 20n,
  clientKeyBytes: 1n << 26n,
  serverKeyBytes: 1n << 30n,
  publicKeyBytes: 1n << 20n,
  provenListBytes: 1n << 20n,
  crsBytes: 1n << 26n
} as const;

/** What a proof of inputs for server key `keyId` is bound to (heaas-core `proof_metadata`). */
export function proofMetadata(keyId: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`he-engine/proof/v1/${keyId}`);
}

export type WorkerRequest =
  | { id: number; kind: 'generateKeys'; passphrase: string }
  | { id: number; kind: 'unlock'; sealed: SealedKey; serverKeySha256: string; passphrase: string }
  /** Seals a raw key stored before passphrases existed, and loads it. */
  | { id: number; kind: 'protect'; clientKey: Uint8Array<ArrayBuffer>; serverKeySha256: string; passphrase: string }
  | { id: number; kind: 'lock' }
  /** Values are decimal strings: 64-bit values do not fit in a JS number. */
  | { id: number; kind: 'encrypt'; type: IntegerType; values: string[] }
  | { id: number; kind: 'decrypt'; type: ValueType; ciphertext: Uint8Array<ArrayBuffer> }
  /**
   * Encrypts `values` under the key's public key into one list with a
   * zero-knowledge proof against the server's CRS (cached in the worker by hash).
   */
  | {
      id: number;
      kind: 'prove';
      type: IntegerType;
      values: string[];
      keyId: string;
      publicKey: Uint8Array<ArrayBuffer>;
      crsSha256: string;
      crs: Uint8Array<ArrayBuffer>;
    };

export interface GeneratedKeys {
  /** The client key, sealed under the passphrase and bound to the server key. */
  sealed: SealedKey;
  compressedServerKey: Uint8Array<ArrayBuffer>;
  /** Hex SHA-256 of `compressedServerKey`, as the server reports it after upload. */
  serverKeySha256: string;
  /** The compact public key proven inputs are encrypted under (not secret). */
  publicKey: Uint8Array<ArrayBuffer>;
}

export type WorkerResult =
  | { kind: 'generateKeys'; keys: GeneratedKeys }
  | { kind: 'unlock' }
  | { kind: 'protect'; sealed: SealedKey }
  | { kind: 'lock' }
  | { kind: 'encrypt'; ciphertexts: Uint8Array<ArrayBuffer>[] }
  /** `"true"`/`"false"` or a decimal integer. */
  | { kind: 'decrypt'; value: string }
  | { kind: 'prove'; list: Uint8Array<ArrayBuffer> };

export type WorkerResponse =
  | { id: number; ok: true; result: WorkerResult }
  | { id: number; ok: false; error: string; wrongPassphrase?: boolean };
