import { describe, expect, it } from 'vitest';
import { keyFileName, parseKeyFile, toKeyFile } from './keyfile.js';
import type { ProtectedClientKey } from './keystore.js';

const record: ProtectedClientKey = {
  keyId: '8e521fee-1111-4222-8333-444455556666',
  serverKeySha256: 'ab'.repeat(32),
  createdAt: '2026-10-27T10:00:00.000Z',
  sealed: {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iterations: 600_000,
    salt: 'c2FsdA==',
    iv: 'aXY=',
    ciphertext: 'Y3Q='
  }
};

describe('key files', () => {
  it('round-trip a protected key and never contain raw key bytes', () => {
    const text = toKeyFile(record);
    expect(JSON.parse(text)).not.toHaveProperty('clientKey');
    const parsed = parseKeyFile(text);
    expect(parsed).toMatchObject({ keyId: record.keyId, serverKeySha256: record.serverKeySha256 });
    expect(parsed.sealed).toEqual(record.sealed);
    expect(keyFileName(record.keyId)).toBe('heaas-key-8e521fee.json');
  });

  it('explain what is wrong with other files', () => {
    expect(() => parseKeyFile('not json')).toThrow('not a HEaaS key file');
    expect(() => parseKeyFile('{"format":"other"}')).toThrow('not a HEaaS key file');
    const newer = { ...JSON.parse(toKeyFile(record)), version: 2 };
    expect(() => parseKeyFile(JSON.stringify(newer))).toThrow('newer version');
    const damaged = { ...JSON.parse(toKeyFile(record)), serverKeySha256: 'xyz' };
    expect(() => parseKeyFile(JSON.stringify(damaged))).toThrow('damaged');
    const weak = JSON.parse(toKeyFile(record));
    weak.sealed.iterations = 1;
    expect(() => parseKeyFile(JSON.stringify(weak))).toThrow('damaged');
  });
});
