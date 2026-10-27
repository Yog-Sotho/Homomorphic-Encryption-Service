import type { GeneratedKeys, WorkerRequest, WorkerResponse, WorkerResult } from './protocol.js';
import { WrongPassphraseError, type SealedKey } from './vault.js';

type Pending = {
  resolve: (result: WorkerResult) => void;
  reject: (error: Error) => void;
};

type RequestBody = WorkerRequest extends infer R ? (R extends { id: number } ? Omit<R, 'id'> : never) : never;

/**
 * Main-thread handle to the TFHE Web Worker. The worker is created lazily on first
 * use. The plaintext client key only ever exists inside it; the page handles it
 * sealed under the user's passphrase.
 */
export class FheClient {
  #worker: Worker | null = null;
  #nextId = 1;
  #pending = new Map<number, Pending>();

  /**
   * TFHE's WASM build uses shared memory, which browsers only allow on
   * cross-origin-isolated pages (COOP same-origin + COEP require-corp).
   */
  static isSupported(): boolean {
    return typeof Worker !== 'undefined' && globalThis.crossOriginIsolated === true;
  }

  #ensureWorker(): Worker {
    if (this.#worker) return this.#worker;
    if (!FheClient.isSupported()) {
      throw new Error(
        'This page is not cross-origin isolated, so in-browser encryption is unavailable.'
      );
    }
    const worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
    worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
      const response = event.data;
      const pending = this.#pending.get(response.id);
      if (!pending) return;
      this.#pending.delete(response.id);
      if (response.ok) pending.resolve(response.result);
      else pending.reject(response.wrongPassphrase ? new WrongPassphraseError() : new Error(response.error));
    });
    worker.addEventListener('error', (event) => {
      const error = new Error(event.message || 'Encryption worker crashed');
      for (const pending of this.#pending.values()) pending.reject(error);
      this.#pending.clear();
      this.#worker = null;
    });
    this.#worker = worker;
    return worker;
  }

  #call(body: RequestBody, transfer: Transferable[] = []): Promise<WorkerResult> {
    const worker = this.#ensureWorker();
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      worker.postMessage({ ...body, id } as WorkerRequest, transfer);
    });
  }

  /**
   * Generates a key pair. The client key stays loaded in the worker and comes
   * back only sealed under `passphrase`.
   */
  async generateKeys(passphrase: string): Promise<GeneratedKeys> {
    const result = await this.#call({ kind: 'generateKeys', passphrase });
    if (result.kind !== 'generateKeys') throw new Error('Unexpected worker reply');
    return result.keys;
  }

  /** Loads a sealed key; rejects with `WrongPassphraseError` if it does not open. */
  async unlock(sealed: SealedKey, serverKeySha256: string, passphrase: string): Promise<void> {
    await this.#call({ kind: 'unlock', sealed, serverKeySha256, passphrase });
  }

  /** Seals and loads a raw key stored before passphrases; returns the sealed form. */
  async protect(
    clientKey: Uint8Array<ArrayBuffer>,
    serverKeySha256: string,
    passphrase: string
  ): Promise<SealedKey> {
    const copy = clientKey.slice();
    const result = await this.#call(
      { kind: 'protect', clientKey: copy, serverKeySha256, passphrase },
      [copy.buffer]
    );
    if (result.kind !== 'protect') throw new Error('Unexpected worker reply');
    return result.sealed;
  }

  /** Forgets the loaded client key. */
  async lock(): Promise<void> {
    await this.#call({ kind: 'lock' });
  }

  async encrypt(values: number[]): Promise<Uint8Array<ArrayBuffer>[]> {
    const result = await this.#call({ kind: 'encrypt', values });
    if (result.kind !== 'encrypt') throw new Error('Unexpected worker reply');
    return result.ciphertexts;
  }

  async decrypt(ciphertext: Uint8Array<ArrayBuffer>): Promise<number> {
    const result = await this.#call({ kind: 'decrypt', ciphertext });
    if (result.kind !== 'decrypt') throw new Error('Unexpected worker reply');
    return result.value;
  }

  terminate(): void {
    this.#worker?.terminate();
    this.#worker = null;
    for (const pending of this.#pending.values()) pending.reject(new Error('Worker terminated'));
    this.#pending.clear();
  }
}
