/**
 * Messages exchanged between the main thread and the TFHE Web Worker.
 *
 * All TFHE work (key generation, encryption, decryption) runs in the worker so the
 * UI stays responsive; byte arrays are transferred, not copied.
 */

/** Size limits passed to TFHE's safe (de)serialization. Mirror the backend's limits. */
export const LIMITS = {
  ciphertextBytes: 1n << 20n,
  clientKeyBytes: 1n << 26n,
  serverKeyBytes: 1n << 30n
} as const;

export type WorkerRequest =
  | { id: number; kind: 'generateKeys' }
  | { id: number; kind: 'loadClientKey'; clientKey: Uint8Array }
  | { id: number; kind: 'encrypt'; values: number[] }
  | { id: number; kind: 'decrypt'; ciphertext: Uint8Array };

export interface GeneratedKeys {
  clientKey: Uint8Array;
  compressedServerKey: Uint8Array;
}

export type WorkerResult =
  | { kind: 'generateKeys'; keys: GeneratedKeys }
  | { kind: 'loadClientKey' }
  | { kind: 'encrypt'; ciphertexts: Uint8Array[] }
  | { kind: 'decrypt'; value: number };

export type WorkerResponse =
  | { id: number; ok: true; result: WorkerResult }
  | { id: number; ok: false; error: string };
