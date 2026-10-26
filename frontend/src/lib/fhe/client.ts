import type { GeneratedKeys, WorkerRequest, WorkerResponse, WorkerResult } from './protocol.js';

type Pending = {
  resolve: (result: WorkerResult) => void;
  reject: (error: Error) => void;
};

type RequestBody = WorkerRequest extends infer R ? (R extends { id: number } ? Omit<R, 'id'> : never) : never;

/**
 * Main-thread handle to the TFHE Web Worker. The worker is created lazily on first
 * use; the client key only ever lives inside it (and in local storage on this device).
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
      else pending.reject(new Error(response.error));
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

  /** Generates a fresh client key (kept in the worker) and its compressed server key. */
  async generateKeys(): Promise<GeneratedKeys> {
    const result = await this.#call({ kind: 'generateKeys' });
    if (result.kind !== 'generateKeys') throw new Error('Unexpected worker reply');
    return result.keys;
  }

  async loadClientKey(clientKey: Uint8Array): Promise<void> {
    // Copy so the caller's buffer survives the transfer.
    const copy = clientKey.slice();
    await this.#call({ kind: 'loadClientKey', clientKey: copy }, [copy.buffer]);
  }

  async encrypt(values: number[]): Promise<Uint8Array[]> {
    const result = await this.#call({ kind: 'encrypt', values });
    if (result.kind !== 'encrypt') throw new Error('Unexpected worker reply');
    return result.ciphertexts;
  }

  async decrypt(ciphertext: Uint8Array): Promise<number> {
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
