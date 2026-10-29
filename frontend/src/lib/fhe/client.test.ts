import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FheClient } from './client.js';
import { proofMetadata, type WorkerRequest, type WorkerResponse } from './protocol.js';
import { WrongPassphraseError } from './vault.js';

/** Stands in for the TFHE worker: answers each request with `reply`. */
class FakeWorker {
  static last: FakeWorker | null = null;
  static reply: (request: WorkerRequest) => WorkerResponse | null = () => null;
  posted: { message: WorkerRequest; transfer: Transferable[] }[] = [];
  terminated = false;
  #listeners: Record<string, ((event: unknown) => void)[]> = {};

  constructor() {
    FakeWorker.last = this;
  }

  addEventListener(type: string, listener: (event: unknown) => void) {
    (this.#listeners[type] ??= []).push(listener);
  }

  postMessage(message: WorkerRequest, transfer: Transferable[] = []) {
    this.posted.push({ message, transfer });
    const response = FakeWorker.reply(message);
    if (response) queueMicrotask(() => this.emit('message', { data: response }));
  }

  emit(type: string, event: unknown) {
    for (const listener of this.#listeners[type] ?? []) listener(event);
  }

  terminate() {
    this.terminated = true;
  }
}

describe('FheClient', () => {
  beforeEach(() => {
    vi.stubGlobal('Worker', FakeWorker);
    vi.stubGlobal('crossOriginIsolated', true);
    FakeWorker.last = null;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('needs a cross-origin isolated page', async () => {
    vi.stubGlobal('crossOriginIsolated', false);
    expect(FheClient.isSupported()).toBe(false);
    await expect(new FheClient().lock()).rejects.toThrow('not cross-origin isolated');
  });

  it('sends typed requests and returns typed results', async () => {
    FakeWorker.reply = (request) => {
      switch (request.kind) {
        case 'encrypt':
          return { id: request.id, ok: true, result: { kind: 'encrypt', ciphertexts: [new Uint8Array(3)] } };
        case 'decrypt':
          return { id: request.id, ok: true, result: { kind: 'decrypt', value: 'true' } };
        case 'prove':
          return { id: request.id, ok: true, result: { kind: 'prove', list: new Uint8Array([9]) } };
        default:
          return { id: request.id, ok: true, result: { kind: 'lock' } };
      }
    };
    const client = new FheClient();
    await expect(client.encrypt('i64', ['-1'])).resolves.toHaveLength(1);
    await expect(client.decrypt('bool', new Uint8Array(1))).resolves.toBe('true');

    const publicKey = new Uint8Array([1, 2]);
    const crs = { sha256: 'ab', bytes: new Uint8Array([3]) };
    await expect(client.prove('u8', ['1', '2'], 'key-1', publicKey, crs)).resolves.toEqual(
      new Uint8Array([9])
    );
    const proveRequest = FakeWorker.last!.posted.at(-1)!.message;
    expect(proveRequest).toMatchObject({ kind: 'prove', type: 'u8', keyId: 'key-1', crsSha256: 'ab' });
    // The public key is copied, so the caller's bytes stay usable.
    expect(publicKey).toEqual(new Uint8Array([1, 2]));

    // Ids are unique per request.
    const ids = FakeWorker.last!.posted.map((p) => p.message.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('maps worker errors, including a wrong passphrase', async () => {
    FakeWorker.reply = (request) =>
      request.kind === 'unlock'
        ? { id: request.id, ok: false, error: 'bad', wrongPassphrase: true }
        : { id: request.id, ok: false, error: 'Unlock your key first' };
    const client = new FheClient();
    const sealed = { v: 1, kdf: 'PBKDF2-SHA256', iterations: 1, salt: '', iv: '', ciphertext: '' } as const;
    await expect(client.unlock(sealed, 'sha', 'pass')).rejects.toBeInstanceOf(WrongPassphraseError);
    await expect(client.encrypt('u16', ['1'])).rejects.toThrow('Unlock your key first');
  });

  it('fails pending requests when the worker crashes or is stopped', async () => {
    FakeWorker.reply = () => null;
    const client = new FheClient();
    const pending = client.decrypt('u16', new Uint8Array(1));
    FakeWorker.last!.emit('error', { message: 'boom' });
    await expect(pending).rejects.toThrow('boom');

    const again = client.lock();
    const worker = FakeWorker.last!;
    client.terminate();
    await expect(again).rejects.toThrow('terminated');
    expect(worker.terminated).toBe(true);
  });
});

describe('proofMetadata', () => {
  it('binds proofs to the key id like the server', () => {
    expect(new TextDecoder().decode(proofMetadata('k-1'))).toBe('he-engine/proof/v1/k-1');
  });
});
