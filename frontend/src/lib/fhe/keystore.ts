/**
 * Client (secret) keys, kept only in this browser's IndexedDB and keyed by the
 * id the server assigned to the matching server key. Nothing here is ever sent
 * to the server. Keys are stored sealed under the user's passphrase (see
 * vault.ts); records from before passphrases existed hold the raw key and are
 * sealed the next time they are unlocked.
 */

import type { SealedKey } from './vault.js';

const DB_NAME = 'heaas';
const DB_VERSION = 1;
const STORE = 'client-keys';

export interface StoredClientKey {
  keyId: string;
  createdAt: string;
  /** SHA-256 (hex) of the matching server key; `sealed` is bound to it. */
  serverKeySha256?: string;
  sealed?: SealedKey;
  /** Unprotected key bytes: only on records stored before passphrases. */
  clientKey?: Uint8Array<ArrayBuffer>;
  /**
   * The compact public key uploaded with the server key (not secret). Proofs
   * must be made with this exact key; keys from before proofs have none.
   */
  publicKey?: Uint8Array<ArrayBuffer>;
}

export type ProtectedClientKey = StoredClientKey & { serverKeySha256: string; sealed: SealedKey };

export function isProtected(record: StoredClientKey): record is ProtectedClientKey {
  return record.sealed !== undefined && record.serverKeySha256 !== undefined;
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE, { keyPath: 'keyId' });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Could not open key storage'));
  });
}

async function run<T>(
  mode: IDBTransactionMode,
  action: (store: IDBObjectStore) => IDBRequest<T>
): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const request = action(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(request.result);
      tx.onerror = () => reject(tx.error ?? new Error('Key storage failed'));
      tx.onabort = () => reject(tx.error ?? new Error('Key storage aborted'));
    });
  } finally {
    db.close();
  }
}

/** Stores (or replaces) a sealed key; a raw key stored under the id is dropped. */
export async function saveSealedKey(
  keyId: string,
  serverKeySha256: string,
  sealed: SealedKey,
  createdAt = new Date().toISOString(),
  publicKey?: Uint8Array<ArrayBuffer>
): Promise<void> {
  const record: ProtectedClientKey = { keyId, serverKeySha256, sealed, createdAt };
  if (publicKey) record.publicKey = publicKey;
  await run('readwrite', (store) => store.put(record));
}

/** Writes a record as is (tests use it to create records in the old format). */
export async function putRecord(record: StoredClientKey): Promise<void> {
  await run('readwrite', (store) => store.put(record));
}

export function getClientKey(keyId: string): Promise<StoredClientKey | undefined> {
  return run<StoredClientKey | undefined>('readonly', (store) => store.get(keyId));
}

export async function deleteClientKey(keyId: string): Promise<void> {
  await run('readwrite', (store) => store.delete(keyId));
}

export function listClientKeys(): Promise<StoredClientKey[]> {
  return run<StoredClientKey[]>('readonly', (store) => store.getAll());
}
