import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { deleteClientKey, getClientKey, listClientKeyIds, saveClientKey } from './keystore.js';

describe('client key store', () => {
  it('saves, loads, lists and deletes keys by server key id', async () => {
    const key = new Uint8Array([9, 8, 7]);
    await saveClientKey('key-a', key);
    await saveClientKey('key-b', new Uint8Array([1]));

    const stored = await getClientKey('key-a');
    expect(stored?.keyId).toBe('key-a');
    expect(Array.from(stored?.clientKey ?? [])).toEqual([9, 8, 7]);
    expect(Date.parse(stored?.createdAt ?? '')).not.toBeNaN();
    expect((await listClientKeyIds()).sort()).toEqual(['key-a', 'key-b']);

    await deleteClientKey('key-a');
    expect(await getClientKey('key-a')).toBeUndefined();
    expect(await listClientKeyIds()).toEqual(['key-b']);
  });

  it('overwrites a key saved twice under the same id', async () => {
    await saveClientKey('key-c', new Uint8Array([1]));
    await saveClientKey('key-c', new Uint8Array([2]));
    expect(Array.from((await getClientKey('key-c'))?.clientKey ?? [])).toEqual([2]);
  });
});
