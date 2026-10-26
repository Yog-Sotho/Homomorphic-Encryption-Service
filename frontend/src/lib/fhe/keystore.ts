/**
 * Client (secret) keys, kept only in this browser's IndexedDB and keyed by the
 * id the server assigned to the matching server key. Nothing here is ever sent
 * to the server.
 */

const DB_NAME = 'heaas';
const DB_VERSION = 1;
const STORE = 'client-keys';

export interface StoredClientKey {
  keyId: string;
  clientKey: Uint8Array;
  createdAt: string;
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

export async function saveClientKey(keyId: string, clientKey: Uint8Array): Promise<void> {
  const record: StoredClientKey = { keyId, clientKey, createdAt: new Date().toISOString() };
  await run('readwrite', (store) => store.put(record));
}

export function getClientKey(keyId: string): Promise<StoredClientKey | undefined> {
  return run<StoredClientKey | undefined>('readonly', (store) => store.get(keyId));
}

export async function deleteClientKey(keyId: string): Promise<void> {
  await run('readwrite', (store) => store.delete(keyId));
}

export async function listClientKeyIds(): Promise<string[]> {
  const keys = await run('readonly', (store) => store.getAllKeys());
  return keys.map(String);
}
