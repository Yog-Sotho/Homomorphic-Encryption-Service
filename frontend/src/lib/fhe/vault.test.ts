import { describe, expect, it } from 'vitest';
import { KDF_ITERATIONS, WrongPassphraseError, isSealedKey, open, seal, sha256Hex } from './vault.js';

// Real deployments use KDF_ITERATIONS; tests use fewer to stay fast.
const FAST = 1_000;
const secret = new Uint8Array([1, 2, 3, 250, 0, 7]);

describe('key vault', () => {
  it('opens with the right passphrase and server key only', async () => {
    const sealed = await seal(secret, 'correct horse battery', 'aa', FAST);
    expect(isSealedKey(sealed)).toBe(true);
    expect(sealed.ciphertext).not.toContain(btoa(String.fromCharCode(...secret)));
    expect(Array.from(await open(sealed, 'correct horse battery', 'aa'))).toEqual(Array.from(secret));

    await expect(open(sealed, 'wrong horse battery', 'aa')).rejects.toBeInstanceOf(WrongPassphraseError);
    // Bound to its server key: the same blob does not open for another one.
    await expect(open(sealed, 'correct horse battery', 'bb')).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it('uses fresh salt and nonce every time', async () => {
    const a = await seal(secret, 'correct horse battery', 'aa', FAST);
    const b = await seal(secret, 'correct horse battery', 'aa', FAST);
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it('defaults to the OWASP iteration count and rejects short passphrases', async () => {
    expect(KDF_ITERATIONS).toBe(600_000);
    await expect(seal(secret, 'short', 'aa', FAST)).rejects.toBeInstanceOf(RangeError);
  });

  it('refuses malformed or tampered blobs', async () => {
    const sealed = await seal(secret, 'correct horse battery', 'aa', FAST);
    expect(isSealedKey({ ...sealed, iterations: 10 })).toBe(false);
    expect(isSealedKey({ ...sealed, kdf: 'MD5' })).toBe(false);
    expect(isSealedKey(null)).toBe(false);
    const bytes = atob(sealed.ciphertext);
    const flipped = btoa(String.fromCharCode(bytes.charCodeAt(0) ^ 1) + bytes.slice(1));
    await expect(
      open({ ...sealed, ciphertext: flipped }, 'correct horse battery', 'aa')
    ).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it('hashes like the server', async () => {
    expect(await sha256Hex(new TextEncoder().encode('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });
});
