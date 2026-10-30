//! Storage for users' compressed server keys.
//!
//! A client generates its TFHE key pair locally and uploads only the compressed
//! server (evaluation) key, which lets the server compute on ciphertexts but not
//! decrypt them. Keys are validated against [`params`](crate::crypto::params) on
//! upload, stored as files named by key id, and decompressed on first use into a
//! small in-memory LRU (a decompressed key is ~180 MB).
//!
//! A key that supports proven inputs also needs the client's compact public key,
//! stored beside it as `<id>.pk`, to check the proofs against.

use crate::crypto::params::{
    compressing_server_key_conformance, legacy_server_key_conformance, server_key_conformance,
    MAX_PUBLIC_KEY_BYTES, PUBLIC_KEY_PARAMETERS,
};
use crate::storage::write_atomic;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tfhe::safe_serialization::safe_deserialize_conformant;
use tfhe::{CompactPublicKey, CompressedServerKey, ServerKey};

/// A user's decompressed server key, ready for evaluation.
pub struct UserServerKey {
    pub server_key: ServerKey,
    /// Made with the compact-public-key parameters (it holds the casting key
    /// proven inputs need).
    pub supports_proofs: bool,
    /// Holds compression keys, so results can be returned as a compressed list.
    pub supports_compression: bool,
}

impl UserServerKey {
    fn from_valid(valid: &ValidKey) -> Self {
        UserServerKey {
            server_key: valid.key.decompress(),
            supports_proofs: valid.supports_proofs,
            supports_compression: valid.supports_compression,
        }
    }
}

/// A checked upload: the key, and what it can do.
pub struct ValidKey {
    pub key: CompressedServerKey,
    pub supports_proofs: bool,
    pub supports_compression: bool,
}

#[derive(Debug)]
pub enum KeyStoreError {
    /// The uploaded bytes are not a usable key; message is safe to show the user.
    Invalid(String),
    NotFound,
    Io(io::Error),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStoreError::Invalid(m) => f.write_str(m),
            KeyStoreError::NotFound => f.write_str("server key not found"),
            KeyStoreError::Io(e) => write!(f, "key store I/O error: {e}"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

impl From<io::Error> for KeyStoreError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            KeyStoreError::NotFound
        } else {
            KeyStoreError::Io(e)
        }
    }
}

/// Parses and checks an uploaded compressed server key: the current parameters
/// (with or without compression keys), or the ones keys from before HE Engine
/// 0.5 were made with. CPU-bound: call from a blocking thread.
pub fn validate_compressed_key(bytes: &[u8], limit: u64) -> Result<ValidKey, KeyStoreError> {
    let configurations = [
        (server_key_conformance(), true, false),
        (compressing_server_key_conformance(), true, true),
        (legacy_server_key_conformance(), false, false),
    ];
    configurations
        .into_iter()
        .find_map(|(conformance, supports_proofs, supports_compression)| {
            safe_deserialize_conformant(bytes, limit, &conformance)
                .ok()
                .map(|key| ValidKey {
                    key,
                    supports_proofs,
                    supports_compression,
                })
        })
        .ok_or_else(|| {
            KeyStoreError::Invalid(
                "Not a compressed server key for this service's parameters \
                 (see GET /api/v1/he/params). Generate it with the same TFHE-rs release."
                    .to_string(),
            )
        })
}

/// Parses and checks an uploaded compact public key.
pub fn validate_public_key(bytes: &[u8]) -> Result<CompactPublicKey, KeyStoreError> {
    safe_deserialize_conformant(bytes, MAX_PUBLIC_KEY_BYTES, &PUBLIC_KEY_PARAMETERS).map_err(|_| {
        KeyStoreError::Invalid("Not a compact public key for this service's parameters".to_string())
    })
}

pub struct KeyStore {
    dir: PathBuf,
    max_key_bytes: u64,
    capacity: usize,
    /// Most recently used last. Small (a handful of entries), so a Vec is fine.
    cache: Mutex<Vec<(String, Arc<UserServerKey>)>>,
    /// One lock per key being decompressed, so jobs that miss the cache for the
    /// same key at once decompress it once (~0.5 s, ~180 MB) and share it.
    loading: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl KeyStore {
    pub fn new(dir: impl Into<PathBuf>, max_key_bytes: u64, capacity: usize) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(KeyStore {
            dir,
            max_key_bytes,
            capacity: capacity.max(1),
            cache: Mutex::new(Vec::new()),
            loading: Mutex::new(HashMap::new()),
        })
    }

    pub fn probe_writable(&self) -> io::Result<()> {
        crate::storage::probe_writable(&self.dir)
    }

    /// Key ids are server-generated UUIDs; anything else never touches the filesystem.
    fn path_for(&self, key_id: &str) -> Result<PathBuf, KeyStoreError> {
        self.file_for(key_id, "bin")
    }

    fn public_key_path(&self, key_id: &str) -> Result<PathBuf, KeyStoreError> {
        self.file_for(key_id, "pk")
    }

    fn file_for(&self, key_id: &str, extension: &str) -> Result<PathBuf, KeyStoreError> {
        let id = uuid::Uuid::parse_str(key_id).map_err(|_| KeyStoreError::NotFound)?;
        Ok(self.dir.join(format!("{}.{extension}", id.hyphenated())))
    }

    /// Stores a validated public key for `key_id`, replacing any earlier one.
    pub fn save_public_key(&self, key_id: &str, bytes: &[u8]) -> Result<(), KeyStoreError> {
        write_atomic(&self.public_key_path(key_id)?, bytes)?;
        Ok(())
    }

    /// The public key uploaded for `key_id`. Small (~33 KB): read per use.
    pub fn load_public_key(&self, key_id: &str) -> Result<CompactPublicKey, KeyStoreError> {
        validate_public_key(&fs::read(self.public_key_path(key_id)?)?)
    }

    /// Writes a validated key durably: temp file, fsync, rename, fsync directory.
    pub fn save(&self, key_id: &str, bytes: &[u8]) -> Result<(), KeyStoreError> {
        write_atomic(&self.path_for(key_id)?, bytes)?;
        Ok(())
    }

    /// Returns the decompressed key, from cache or disk. CPU-heavy on a miss
    /// (~0.5 s): call from a blocking thread.
    pub fn load(&self, key_id: &str) -> Result<Arc<UserServerKey>, KeyStoreError> {
        if let Some(key) = self.cached(key_id) {
            crate::telemetry::METRICS.key_cache_lookup(true);
            return Ok(key);
        }
        let lock = self
            .loading
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key_id.to_string())
            .or_default()
            .clone();
        let loaded = {
            let _loading = lock.lock().unwrap_or_else(|e| e.into_inner());
            // Another job may have decompressed it while this one waited.
            match self.cached(key_id) {
                Some(key) => {
                    crate::telemetry::METRICS.key_cache_lookup(true);
                    Ok(key)
                }
                None => {
                    crate::telemetry::METRICS.key_cache_lookup(false);
                    self.decompress(key_id)
                }
            }
        };
        let mut loading = self.loading.lock().unwrap_or_else(|e| e.into_inner());
        // The map and this call hold the lock: no one else is waiting on it.
        if Arc::strong_count(&lock) == 2 {
            loading.remove(key_id);
        }
        loaded
    }

    /// Reads, validates and decompresses a key, and caches it.
    fn decompress(&self, key_id: &str) -> Result<Arc<UserServerKey>, KeyStoreError> {
        let bytes = fs::read(self.path_for(key_id)?)?;
        // Re-validated on load as well: the file is the only copy of the key.
        let valid = validate_compressed_key(&bytes, self.max_key_bytes)?;
        let key = Arc::new(UserServerKey::from_valid(&valid));

        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.retain(|(id, _)| id != key_id);
        if cache.len() >= self.capacity {
            cache.remove(0);
        }
        cache.push((key_id.to_string(), key.clone()));
        Ok(key)
    }

    fn cached(&self, key_id: &str) -> Option<Arc<UserServerKey>> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let pos = cache.iter().position(|(id, _)| id == key_id)?;
        let entry = cache.remove(pos);
        let key = entry.1.clone();
        cache.push(entry);
        Some(key)
    }

    /// Deletes the stored key and evicts it from memory. Missing files are fine.
    pub fn remove(&self, key_id: &str) -> Result<(), KeyStoreError> {
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(id, _)| id != key_id);
        for path in [self.public_key_path(key_id)?, self.path_for(key_id)?] {
            match fs::remove_file(path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(KeyStoreError::Io(e)),
                _ => {}
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn contains_file(&self, key_id: &str) -> bool {
        self.path_for(key_id).map(|p| p.exists()).unwrap_or(false)
    }
}

/// Shared, lazily generated TFHE keys for tests (key generation is slow).
#[cfg(test)]
pub mod test_support {
    use super::*;
    use crate::crypto::params::{compressing_tfhe_config, tfhe_config};
    use std::sync::OnceLock;
    use tfhe::safe_serialization::safe_serialize;
    use tfhe::ClientKey;

    struct Fixture {
        client_key: ClientKey,
        compressed_bytes: Vec<u8>,
        public_key: CompactPublicKey,
        public_key_bytes: Vec<u8>,
        server_key: Arc<UserServerKey>,
    }

    fn make_fixture(config: tfhe::Config) -> Fixture {
        let client_key = ClientKey::generate(config);
        let compressed = CompressedServerKey::new(&client_key);
        let mut compressed_bytes = Vec::new();
        safe_serialize(&compressed, &mut compressed_bytes, 1 << 30).unwrap();
        let public_key = CompactPublicKey::new(&client_key);
        let mut public_key_bytes = Vec::new();
        safe_serialize(&public_key, &mut public_key_bytes, MAX_PUBLIC_KEY_BYTES).unwrap();
        let valid = validate_compressed_key(&compressed_bytes, 1 << 30).unwrap();
        let server_key = Arc::new(UserServerKey::from_valid(&valid));
        Fixture {
            client_key,
            compressed_bytes,
            public_key,
            public_key_bytes,
            server_key,
        }
    }

    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| make_fixture(tfhe_config()))
    }

    /// A second key pair, made with compression keys.
    fn compressing_fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| make_fixture(compressing_tfhe_config()))
    }

    /// The client key and server key of the pair with compression keys.
    pub fn compressing_keys() -> (&'static ClientKey, Arc<UserServerKey>) {
        let f = compressing_fixture();
        (&f.client_key, f.server_key.clone())
    }

    /// What a client with compression keys uploads to `POST /api/v1/keys`.
    pub fn compressing_server_key_bytes() -> &'static [u8] {
        &compressing_fixture().compressed_bytes
    }

    /// The client's compact public key, which proven inputs are encrypted under.
    pub fn public_key() -> &'static CompactPublicKey {
        &fixture().public_key
    }

    /// What a client uploads to `PUT /api/v1/keys/{id}/public-key`.
    pub fn public_key_bytes() -> &'static [u8] {
        &fixture().public_key_bytes
    }

    /// The client's secret key. Only tests ever hold one on the server side.
    pub fn client_key() -> &'static ClientKey {
        &fixture().client_key
    }

    /// What a client uploads to `POST /api/v1/keys`.
    pub fn compressed_server_key_bytes() -> &'static [u8] {
        &fixture().compressed_bytes
    }

    pub fn user_server_key() -> Arc<UserServerKey> {
        fixture().server_key.clone()
    }

    /// A fresh, empty key store directory under the system temp dir.
    pub fn temp_store_dir() -> PathBuf {
        std::env::temp_dir().join(format!("heaas-keys-{}", uuid::Uuid::new_v4()))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use tfhe::safe_serialization::safe_serialize;
    use tfhe::ClientKey;

    #[test]
    fn accepts_a_conforming_key_and_rejects_others() {
        let bytes = compressed_server_key_bytes();
        let valid = validate_compressed_key(bytes, 1 << 30).unwrap();
        assert!(valid.supports_proofs && !valid.supports_compression);
        let compressing = validate_compressed_key(compressing_server_key_bytes(), 1 << 30).unwrap();
        assert!(compressing.supports_proofs && compressing.supports_compression);

        // Keys from before 0.5 (no compact-public-key parameters) still work.
        let mut legacy = Vec::new();
        safe_serialize(
            &CompressedServerKey::new(&ClientKey::generate(
                crate::crypto::params::legacy_tfhe_config(),
            )),
            &mut legacy,
            1 << 30,
        )
        .unwrap();
        assert!(
            !validate_compressed_key(&legacy, 1 << 30)
                .unwrap()
                .supports_proofs
        );

        // Over the size limit.
        assert!(matches!(
            validate_compressed_key(bytes, 1024),
            Err(KeyStoreError::Invalid(_))
        ));
        // Garbage and truncation.
        assert!(validate_compressed_key(b"garbage", 1 << 30).is_err());
        assert!(validate_compressed_key(&bytes[..bytes.len() / 2], 1 << 30).is_err());

        // A real key generated under different parameters.
        let foreign = tfhe::ConfigBuilder::with_custom_parameters(
            tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        )
        .build();
        let mut foreign_bytes = Vec::new();
        safe_serialize(
            &CompressedServerKey::new(&ClientKey::generate(foreign)),
            &mut foreign_bytes,
            1 << 30,
        )
        .unwrap();
        assert!(matches!(
            validate_compressed_key(&foreign_bytes, 1 << 30),
            Err(KeyStoreError::Invalid(_))
        ));
    }

    #[test]
    fn saves_loads_caches_and_removes_keys() {
        let dir = temp_store_dir();
        let store = KeyStore::new(&dir, 1 << 30, 1).unwrap();
        let id = uuid::Uuid::new_v4().to_string();

        store.save(&id, compressed_server_key_bytes()).unwrap();
        assert!(store.contains_file(&id));
        assert!(matches!(
            store.load_public_key(&id),
            Err(KeyStoreError::NotFound)
        ));
        store.save_public_key(&id, public_key_bytes()).unwrap();
        store.load_public_key(&id).unwrap();
        assert!(validate_public_key(b"nonsense").is_err());
        assert!(validate_public_key(compressed_server_key_bytes()).is_err());
        let first = store.load(&id).unwrap();
        let second = store.load(&id).unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "second load is served from cache"
        );

        store.remove(&id).unwrap();
        assert!(!store.contains_file(&id));
        assert!(matches!(store.load(&id), Err(KeyStoreError::NotFound)));
        assert!(matches!(
            store.load_public_key(&id),
            Err(KeyStoreError::NotFound)
        ));
        store.remove(&id).unwrap(); // idempotent
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_cache_misses_decompress_a_key_once() {
        let dir = temp_store_dir();
        let store = Arc::new(KeyStore::new(&dir, 1 << 30, 2).unwrap());
        let id = uuid::Uuid::new_v4().to_string();
        store.save(&id, compressed_server_key_bytes()).unwrap();
        let loads: Vec<_> = (0..3)
            .map(|_| {
                let (store, id) = (store.clone(), id.clone());
                std::thread::spawn(move || store.load(&id).unwrap())
            })
            .collect();
        let keys: Vec<_> = loads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(
            keys.iter().all(|k| Arc::ptr_eq(k, &keys[0])),
            "every load shares one decompressed key"
        );
        assert!(store.loading.lock().unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_non_uuid_ids_before_touching_the_filesystem() {
        let dir = temp_store_dir();
        let store = KeyStore::new(&dir, 1 << 30, 1).unwrap();
        for id in ["../../etc/passwd", "a/b", "", "not-a-uuid"] {
            assert!(
                matches!(store.save(id, b"x"), Err(KeyStoreError::NotFound)),
                "{id}"
            );
            assert!(
                matches!(store.load(id), Err(KeyStoreError::NotFound)),
                "{id}"
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
