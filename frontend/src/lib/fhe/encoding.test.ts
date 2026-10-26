import { describe, expect, it } from 'vitest';
import { base64ToBytes, bytesToBase64 } from './encoding.js';

describe('base64 encoding', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 127, 128, 254, 255]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it('matches Node base64 for a ciphertext-sized buffer without overflowing the stack', () => {
    const bytes = new Uint8Array(132_101).map((_, i) => (i * 31) % 256);
    const encoded = bytesToBase64(bytes);
    expect(encoded).toBe(Buffer.from(bytes).toString('base64'));
    expect(base64ToBytes(encoded)).toEqual(bytes);
  });

  it('handles empty input', () => {
    expect(bytesToBase64(new Uint8Array())).toBe('');
    expect(base64ToBytes('')).toEqual(new Uint8Array());
  });
});
