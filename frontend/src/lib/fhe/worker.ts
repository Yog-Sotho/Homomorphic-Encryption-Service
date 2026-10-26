/// <reference lib="webworker" />
import init, {
  FheUint16,
  initThreadPool,
  TfheClientKey,
  TfheCompressedServerKey,
  TfheConfigBuilder
} from 'tfhe';
import { LIMITS, type WorkerRequest, type WorkerResponse, type WorkerResult } from './protocol.js';

declare const self: DedicatedWorkerGlobalScope;

let ready: Promise<void> | null = null;
let clientKey: TfheClientKey | null = null;

/** Loads the WASM module and starts TFHE's rayon thread pool (needs cross-origin isolation). */
function ensureReady(): Promise<void> {
  ready ??= (async () => {
    await init();
    // Leave one core for the page so the UI stays responsive during keygen.
    await initThreadPool(Math.max(1, (navigator.hardwareConcurrency || 2) - 1));
  })();
  return ready;
}

function requireClientKey(): TfheClientKey {
  if (!clientKey) throw new Error('No client key loaded');
  return clientKey;
}

function assertUint16(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError(`Value ${value} is not an unsigned 16-bit integer`);
  }
}

async function handle(request: WorkerRequest): Promise<WorkerResult> {
  await ensureReady();
  switch (request.kind) {
    case 'generateKeys': {
      // Must match the server's ConfigBuilder::default() (see backend crypto/params.rs).
      const config = TfheConfigBuilder.default().build();
      const key = TfheClientKey.generate(config);
      const serverKey = TfheCompressedServerKey.new(key);
      const keys = {
        clientKey: key.safe_serialize(LIMITS.clientKeyBytes),
        compressedServerKey: serverKey.safe_serialize(LIMITS.serverKeyBytes)
      };
      serverKey.free();
      clientKey?.free();
      clientKey = key;
      return { kind: 'generateKeys', keys };
    }
    case 'loadClientKey': {
      const key = TfheClientKey.safe_deserialize(request.clientKey, LIMITS.clientKeyBytes);
      clientKey?.free();
      clientKey = key;
      return { kind: 'loadClientKey' };
    }
    case 'encrypt': {
      const key = requireClientKey();
      const ciphertexts = request.values.map((value) => {
        assertUint16(value);
        const ct = FheUint16.encrypt_with_client_key(value, key);
        try {
          return ct.safe_serialize(LIMITS.ciphertextBytes);
        } finally {
          ct.free();
        }
      });
      return { kind: 'encrypt', ciphertexts };
    }
    case 'decrypt': {
      const ct = FheUint16.safe_deserialize(request.ciphertext, LIMITS.ciphertextBytes);
      try {
        return { kind: 'decrypt', value: ct.decrypt(requireClientKey()) };
      } finally {
        ct.free();
      }
    }
  }
}

function transferables(result: WorkerResult): Transferable[] {
  switch (result.kind) {
    case 'generateKeys':
      return [result.keys.clientKey.buffer, result.keys.compressedServerKey.buffer];
    case 'encrypt':
      return result.ciphertexts.map((ct) => ct.buffer);
    default:
      return [];
  }
}

self.addEventListener('message', (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;
  handle(request).then(
    (result) => {
      const response: WorkerResponse = { id: request.id, ok: true, result };
      self.postMessage(response, transferables(result));
    },
    (error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      const response: WorkerResponse = { id: request.id, ok: false, error: message };
      self.postMessage(response);
    }
  );
});
