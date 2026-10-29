/// <reference lib="webworker" />
import init, {
  CompactCiphertextList,
  CompactPkeCrs,
  FheBool,
  FheInt16,
  FheInt32,
  FheInt64,
  FheInt8,
  FheUint16,
  FheUint32,
  FheUint64,
  FheUint8,
  initThreadPool,
  ShortintCompactPublicKeyEncryptionParameters,
  ShortintCompactPublicKeyEncryptionParametersName,
  TfheClientKey,
  TfheCompactPublicKey,
  TfheCompressedServerKey,
  TfheConfigBuilder,
  ZkComputeLoad,
  type CompactCiphertextListBuilder
} from 'tfhe';
import type { IntegerType, ValueType } from '../api.js';
import { parseValue } from './operations.js';
import {
  LIMITS,
  proofMetadata,
  type WorkerRequest,
  type WorkerResponse,
  type WorkerResult
} from './protocol.js';
import { WrongPassphraseError, open, seal, sha256Hex } from './vault.js';

declare const self: DedicatedWorkerGlobalScope;

let ready: Promise<void> | null = null;
let clientKey: TfheClientKey | null = null;
/** The last CRS used, deserialized (that takes a while): proofs reuse it. */
let crsCache: { sha256: string; crs: CompactPkeCrs } | null = null;

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

/** Runs `use` on a TFHE object and frees it (WASM memory is not garbage collected). */
function using<T extends { free(): void }, R>(object: T, use: (object: T) => R): R {
  try {
    return use(object);
  } finally {
    object.free();
  }
}

function checkedValue(type: IntegerType, text: string): bigint {
  const value = parseValue(type, text);
  if (value === null) throw new RangeError(`${text} is not a valid ${type} value`);
  return value;
}

/** Encrypts one value as `type`'s ciphertext, serialized. */
function encryptAs(type: IntegerType, value: bigint, key: TfheClientKey): Uint8Array<ArrayBuffer> {
  const n = Number(value);
  const ciphertext = (() => {
    switch (type) {
      case 'u8':
        return FheUint8.encrypt_with_client_key(n, key);
      case 'u16':
        return FheUint16.encrypt_with_client_key(n, key);
      case 'u32':
        return FheUint32.encrypt_with_client_key(n, key);
      case 'u64':
        return FheUint64.encrypt_with_client_key(value, key);
      case 'i8':
        return FheInt8.encrypt_with_client_key(n, key);
      case 'i16':
        return FheInt16.encrypt_with_client_key(n, key);
      case 'i32':
        return FheInt32.encrypt_with_client_key(n, key);
      case 'i64':
        return FheInt64.encrypt_with_client_key(value, key);
    }
  })();
  return using(ciphertext, (ct) => owned(ct.safe_serialize(LIMITS.ciphertextBytes)));
}

/** Decrypts a serialized ciphertext of `type`; the value as a string. */
function decryptAs(type: ValueType, bytes: Uint8Array, key: TfheClientKey): string {
  const limit = LIMITS.ciphertextBytes;
  const decrypt = (ct: { decrypt(key: TfheClientKey): number | bigint | boolean; free(): void }) =>
    using(ct, (c) => String(c.decrypt(key)));
  switch (type) {
    case 'bool':
      return decrypt(FheBool.safe_deserialize(bytes, limit));
    case 'u8':
      return decrypt(FheUint8.safe_deserialize(bytes, limit));
    case 'u16':
      return decrypt(FheUint16.safe_deserialize(bytes, limit));
    case 'u32':
      return decrypt(FheUint32.safe_deserialize(bytes, limit));
    case 'u64':
      return decrypt(FheUint64.safe_deserialize(bytes, limit));
    case 'i8':
      return decrypt(FheInt8.safe_deserialize(bytes, limit));
    case 'i16':
      return decrypt(FheInt16.safe_deserialize(bytes, limit));
    case 'i32':
      return decrypt(FheInt32.safe_deserialize(bytes, limit));
    case 'i64':
      return decrypt(FheInt64.safe_deserialize(bytes, limit));
  }
}

function push(builder: CompactCiphertextListBuilder, type: IntegerType, value: bigint): void {
  const n = Number(value);
  switch (type) {
    case 'u8':
      return builder.push_u8(n);
    case 'u16':
      return builder.push_u16(n);
    case 'u32':
      return builder.push_u32(n);
    case 'u64':
      return builder.push_u64(value);
    case 'i8':
      return builder.push_i8(n);
    case 'i16':
      return builder.push_i16(n);
    case 'i32':
      return builder.push_i32(n);
    case 'i64':
      return builder.push_i64(value);
  }
}

function loadCrs(sha256: string, bytes: Uint8Array): CompactPkeCrs {
  if (crsCache?.sha256 === sha256) return crsCache.crs;
  const crs = CompactPkeCrs.safe_deserialize(bytes, LIMITS.crsBytes);
  crsCache?.crs.free();
  crsCache = { sha256, crs };
  return crs;
}

async function handle(request: WorkerRequest): Promise<WorkerResult> {
  await ensureReady();
  switch (request.kind) {
    case 'generateKeys': {
      // Must match the server's tfhe_config() (heaas-core params.rs): the default
      // parameters plus the compact-public-key ones (this name also selects the
      // matching casting parameters).
      const publicKeyParams = new ShortintCompactPublicKeyEncryptionParameters(
        ShortintCompactPublicKeyEncryptionParametersName.PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
      );
      const config = TfheConfigBuilder.default()
        .use_dedicated_compact_public_key_parameters(publicKeyParams)
        .build();
      publicKeyParams.free();
      const key = TfheClientKey.generate(config);
      const compressedServerKey = using(TfheCompressedServerKey.new(key), (k) =>
        owned(k.safe_serialize(LIMITS.serverKeyBytes))
      );
      const publicKey = using(TfheCompactPublicKey.new(key), (k) =>
        owned(k.safe_serialize(LIMITS.publicKeyBytes))
      );
      const serverKeySha256 = await sha256Hex(compressedServerKey);
      const raw = owned(key.safe_serialize(LIMITS.clientKeyBytes));
      const sealed = await seal(raw, request.passphrase, serverKeySha256);
      raw.fill(0);
      useClientKey(key);
      return {
        kind: 'generateKeys',
        keys: { sealed, compressedServerKey, serverKeySha256, publicKey }
      };
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
      const values = request.values.map((v) => checkedValue(request.type, v));
      const ciphertexts = values.map((value) => encryptAs(request.type, value, key));
      return { kind: 'encrypt', ciphertexts };
    }
    case 'decrypt': {
      return { kind: 'decrypt', value: decryptAs(request.type, request.ciphertext, requireClientKey()) };
    }
    case 'prove': {
      const values = request.values.map((v) => checkedValue(request.type, v));
      const crs = loadCrs(request.crsSha256, request.crs);
      const list = using(
        TfheCompactPublicKey.safe_deserialize(request.publicKey, LIMITS.publicKeyBytes),
        (publicKey) => {
          const builder = CompactCiphertextList.builder(publicKey);
          for (const value of values) push(builder, request.type, value);
          const proven = builder.build_with_proof_packed(
            crs,
            proofMetadata(request.keyId),
            ZkComputeLoad.Proof
          );
          builder.free();
          return using(proven, (p) => owned(p.safe_serialize(LIMITS.provenListBytes)));
        }
      );
      return { kind: 'prove', list };
    }
  }
}

function transferables(result: WorkerResult): Transferable[] {
  switch (result.kind) {
    case 'generateKeys':
      return [result.keys.compressedServerKey.buffer, result.keys.publicKey.buffer];
    case 'encrypt':
      return result.ciphertexts.map((ct) => ct.buffer);
    case 'prove':
      return [result.list.buffer];
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
