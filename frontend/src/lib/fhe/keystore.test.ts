import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import {
  deleteClientKey,
  getClientKey,
  isProtected,
  listClientKeys,
  putRecord,
  saveSealedKey
} from './keystore.js';
import type { SealedKey } from './vault.js';

const sealed: SealedKey = {
  v: 1,
  kdf: 'PBKDF2-SHA256',
  iterations: 600_000,
  salt: 's',
  iv: 'i',
  ciphertext: 'c'
};

describe('client key store', () => {
  it('saves, loads, lists and deletes sealed keys by server key id', async () => {
    await saveSealedKey('key-a', 'hash-a', sealed);
    await saveSealedKey('key-b', 'hash-b', sealed, '2026-01-01T00:00:00.000Z');

    const stored = await getClientKey('key-a');
    expect(stored && isProtected(stored)).toBe(true);
    expect(stored?.serverKeySha256).toBe('hash-a');
    expect(stored?.clientKey).toBeUndefined();
    expect(Date.parse(stored?.createdAt ?? '')).not.toBeNaN();
    expect((await listClientKeys()).map((k) => k.keyId).sort()).toEqual(['key-a', 'key-b']);

    await deleteClientKey('key-a');
    expect(await getClientKey('key-a')).toBeUndefined();
    expect((await listClientKeys()).map((k) => k.keyId)).toEqual(['key-b']);
    await deleteClientKey('key-b');
  });

  it('reads unprotected keys from before passphrases and replaces them when sealed', async () => {
    await putRecord({
      keyId: 'old',
      clientKey: new Uint8Array([1, 2]),
      createdAt: '2026-10-01T00:00:00Z'
    });
    const legacy = await getClientKey('old');
    expect(legacy && isProtected(legacy)).toBe(false);
    expect(Array.from(legacy?.clientKey ?? [])).toEqual([1, 2]);

    await saveSealedKey('old', 'hash', sealed, legacy?.createdAt);
    const upgraded = await getClientKey('old');
    expect(upgraded?.clientKey).toBeUndefined();
    expect(upgraded?.createdAt).toBe('2026-10-01T00:00:00Z');
  });
});
