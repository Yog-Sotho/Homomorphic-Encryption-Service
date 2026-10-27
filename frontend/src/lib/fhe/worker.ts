/// <reference lib="webworker" />
import init, {
  FheUint16,
  initThreadPool,
  TfheClientKey,
  TfheCompressedServerKey,
  TfheConfigBuilder
} from 'tfhe';
import { LIMITS, type WorkerRequest, type WorkerResponse, type WorkerResult } from './protocol.js';
import { WrongPassphraseError, open, seal, sha256Hex } from './vault.js';

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
  if (!clientKey) throw new Error('Unlock your key first');
  return clientKey;
}

function useClientKey(key: TfheClientKey): void {
  clientKey?.free();
  clientKey = key;
}

/** Parses raw client key bytes, then overwrites them: no plaintext copy lingers. */
function loadRawKey(bytes: Uint8Array<ArrayBuffer>): TfheClientKey {
  try {
    return TfheClientKey.safe_deserialize(bytes, LIMITS.clientKeyBytes);
  } finally {
    bytes.fill(0);
  }
}

/**
 * tfhe's bindings type their output as possibly shared memory; WebCrypto and
 * transfers need a plain ArrayBuffer. They already return a fresh copy, so this
 * only copies again if that ever changes.
 */
function owned(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.buffer instanceof ArrayBuffer
    ? (bytes as Uint8Array<ArrayBuffer>)
    : new Uint8Array(bytes);
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
      const compressedServerKey = owned(serverKey.safe_serialize(LIMITS.serverKeyBytes));
      serverKey.free();
      const serverKeySha256 = await sha256Hex(compressedServerKey);
      const raw = owned(key.safe_serialize(LIMITS.clientKeyBytes));
      const sealed = await seal(raw, request.passphrase, serverKeySha256);
      raw.fill(0);
      useClientKey(key);
      return { kind: 'generateKeys', keys: { sealed, compressedServerKey, serverKeySha256 } };
    }
    case 'unlock': {
      const raw = await open(request.sealed, request.passphrase, request.serverKeySha256);
      useClientKey(loadRawKey(raw));
      return { kind: 'unlock' };
    }
    case 'protect': {
      const sealed = await seal(request.clientKey, request.passphrase, request.serverKeySha256);
      useClientKey(loadRawKey(request.clientKey));
      return { kind: 'protect', sealed };
    }
    case 'lock': {
      clientKey?.free();
      clientKey = null;
      return { kind: 'lock' };
    }
    case 'encrypt': {
      const key = requireClientKey();
      const ciphertexts = request.values.map((value) => {
        assertUint16(value);
        const ct = FheUint16.encrypt_with_client_key(value, key);
        try {
          return owned(ct.safe_serialize(LIMITS.ciphertextBytes));
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
      return [result.keys.compressedServerKey.buffer];
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
      const response: WorkerResponse = {
        id: request.id,
        ok: false,
        error: message,
        wrongPassphrase: error instanceof WrongPassphraseError
      };
      self.postMessage(response);
    }
  );
});
