/**
 * The page's single TFHE worker and which key is unlocked in it, shared by every
 * page so a key unlocked on one stays unlocked across in-app navigation. A reload
 * (or signing out) forgets it: the passphrase is needed again.
 */

import { he, keys, type IntegerType, type ServerKeyInfo, type ValueType } from '../api.js';
import { FheClient } from './client.js';
import { keyFilePublicKey, parseKeyFile } from './keyfile.js';
import {
  deleteClientKey,
  getClientKey,
  isProtected,
  listClientKeys,
  saveSealedKey,
  type StoredClientKey
} from './keystore.js';
import { sha256Hex } from './vault.js';

/** A server key with whatever this browser holds for it. */
export interface KeyEntry {
  server: ServerKeyInfo;
  /** `undefined`: the client key is not in this browser. */
  local?: StoredClientKey;
}

export interface KeyOverview {
  entries: KeyEntry[];
  /** Client keys whose server key no longer exists. */
  orphans: StoredClientKey[];
}

/** Whether proven inputs can be sent for this key from this browser. */
export function canProve(entry: KeyEntry): boolean {
  return entry.server.supports_proofs && entry.local?.publicKey !== undefined;
}

export async function loadKeyOverview(): Promise<KeyOverview> {
  const [server, local] = await Promise.all([keys.list(), listClientKeys()]);
  const byId = new Map(local.map((k) => [k.keyId, k]));
  return {
    entries: server.map((s) => ({ server: s, local: byId.get(s.id) })),
    orphans: local.filter((k) => !server.some((s) => s.id === k.keyId))
  };
}

class FheSession {
  /** The server key whose client key is loaded in the worker, if any. */
  unlockedKeyId = $state<string | null>(null);
  #client: FheClient | null = null;
  #crs: Promise<{ sha256: string; bytes: Uint8Array<ArrayBuffer> }> | null = null;

  get supported(): boolean {
    return FheClient.isSupported();
  }

  get #worker(): FheClient {
    this.#client ??= new FheClient();
    return this.#client;
  }

  /**
   * Generates a key pair in the worker, registers the server key and stores the
   * client key sealed under `passphrase`. The new key is left unlocked.
   */
  async generate(passphrase: string, onUploading?: () => void): Promise<ServerKeyInfo> {
    const generated = await this.#worker.generateKeys(passphrase);
    onUploading?.();
    let info = await keys.upload(generated.compressedServerKey);
    try {
      if (info.sha256 !== generated.serverKeySha256) {
        throw new Error('The server registered a different key than this browser sent.');
      }
      if (info.supports_proofs) {
        info = await keys.uploadPublicKey(info.id, generated.publicKey);
      }
      await saveSealedKey(
        info.id,
        generated.serverKeySha256,
        generated.sealed,
        undefined,
        generated.publicKey
      );
    } catch (e) {
      // Without its client key the server key is useless; don't leave it behind.
      await keys.remove(info.id).catch(() => {});
      await this.lock();
      throw e;
    }
    this.unlockedKeyId = info.id;
    return info;
  }

  /**
   * Unlocks a stored key. A key stored before passphrases existed is sealed
   * under `passphrase` now, replacing the unprotected copy.
   */
  async unlock(entry: KeyEntry & { local: StoredClientKey }, passphrase: string): Promise<void> {
    // Entries usually come from page state; reactive proxies cannot be posted to a worker.
    const { server, local } = $state.snapshot(entry) as typeof entry;
    if (isProtected(local)) {
      await this.#worker.unlock(local.sealed, local.serverKeySha256, passphrase);
    } else if (local.clientKey) {
      const sealed = await this.#worker.protect(local.clientKey, server.sha256, passphrase);
      await saveSealedKey(local.keyId, server.sha256, sealed, local.createdAt);
    } else {
      throw new Error('This stored key is damaged.');
    }
    this.unlockedKeyId = local.keyId;
  }

  /** Restores a key from a backup file into this browser and unlocks it. */
  async importKeyFile(text: string, passphrase: string, serverKeys: ServerKeyInfo[]): Promise<string> {
    const file = parseKeyFile(text);
    const server = serverKeys.find((k) => k.id === file.keyId);
    if (!server) {
      throw new Error('This key is not registered to your account, or it was deleted.');
    }
    if (server.sha256 !== file.serverKeySha256) {
      throw new Error('This key file does not belong to the registered key with that id.');
    }
    // Opening it proves the passphrase before anything is stored.
    await this.#worker.unlock(file.sealed, file.serverKeySha256, passphrase);
    const publicKey = keyFilePublicKey(file);
    await saveSealedKey(file.keyId, file.serverKeySha256, file.sealed, file.createdAt, publicKey);
    if (publicKey && server.supports_proofs && !server.has_public_key) {
      await keys.uploadPublicKey(file.keyId, publicKey);
    }
    this.unlockedKeyId = file.keyId;
    return file.keyId;
  }

  /** Deletes a key on the server and in this browser. */
  async remove(keyId: string): Promise<void> {
    await keys.remove(keyId);
    await this.forget(keyId);
  }

  /** Deletes a key from this browser only (e.g. one the server no longer has). */
  async forget(keyId: string): Promise<void> {
    await deleteClientKey(keyId);
    if (this.unlockedKeyId === keyId) await this.lock();
  }

  async lock(): Promise<void> {
    if (this.#client) await this.#client.lock();
    this.unlockedKeyId = null;
  }

  encrypt(type: IntegerType, values: string[]): Promise<Uint8Array<ArrayBuffer>[]> {
    return this.#worker.encrypt(type, values);
  }

  decrypt(type: ValueType, ciphertext: Uint8Array<ArrayBuffer>): Promise<string> {
    return this.#worker.decrypt(type, ciphertext);
  }

  /** The server's CRS, downloaded once and checked against its advertised hash. */
  #loadCrs(): Promise<{ sha256: string; bytes: Uint8Array<ArrayBuffer> }> {
    this.#crs ??= (async () => {
      const params = await he.params();
      if (!params.proofs) throw new Error('This server does not accept proven inputs.');
      const bytes = await he.crs();
      const sha256 = await sha256Hex(bytes);
      if (sha256 !== params.proofs.crs_sha256) {
        throw new Error('The proof parameters downloaded do not match the server’s.');
      }
      return { sha256, bytes };
    })();
    this.#crs.catch(() => (this.#crs = null));
    return this.#crs;
  }

  /**
   * Encrypts `values` under the key's public key into one list with a proof
   * that they are well-formed encryptions, for the job's `proven_inputs`.
   */
  async prove(keyId: string, type: IntegerType, values: string[]): Promise<Uint8Array<ArrayBuffer>> {
    const publicKey = (await getClientKey(keyId))?.publicKey;
    if (!publicKey) throw new Error('This key has no public key in this browser.');
    return this.#worker.prove(type, values, keyId, publicKey, await this.#loadCrs());
  }

  /** Stops the worker (and with it the loaded key), e.g. on sign-out. */
  reset(): void {
    this.#client?.terminate();
    this.#client = null;
    this.unlockedKeyId = null;
  }
}

export const fheSession = new FheSession();
