//! Local TFHE operations: key generation, encryption and decryption. Nothing
//! here talks to the server; the client key never leaves this process unless
//! you save it.

use crate::error::{Error, Result};
use heaas_core::params::{
    tfhe_config, MAX_CIPHERTEXT_BYTES, MAX_CLIENT_KEY_BYTES, MAX_SERVER_KEY_BYTES,
};
use std::io::Write;
use std::path::Path;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_deserialize_conformant, safe_serialize};
use tfhe::{ClientKey, CompressedServerKey, FheUint16, FheUint16ConformanceParams};

pub use tfhe::ClientKey as SecretKey;

/// A new key pair with the server's parameters. Takes seconds: the compressed
/// server key is ~60 MB.
pub fn generate_keys() -> (ClientKey, CompressedServerKey) {
    let client = ClientKey::generate(tfhe_config());
    let server = CompressedServerKey::new(&client);
    (client, server)
}

/// The bytes to upload with [`crate::Client::upload_key`].
pub fn server_key_bytes(key: &CompressedServerKey) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    safe_serialize(key, &mut bytes, MAX_SERVER_KEY_BYTES)
        .map_err(|e| Error::Encoding(format!("serializing the server key: {e}")))?;
    Ok(bytes)
}

pub fn client_key_bytes(key: &ClientKey) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    safe_serialize(key, &mut bytes, MAX_CLIENT_KEY_BYTES)
        .map_err(|e| Error::Encoding(format!("serializing the client key: {e}")))?;
    Ok(bytes)
}

pub fn client_key_from_bytes(bytes: &[u8]) -> Result<ClientKey> {
    safe_deserialize(bytes, MAX_CLIENT_KEY_BYTES)
        .map_err(|e| Error::Encoding(format!("not a TFHE-rs client key: {e}")))
}

/// Encrypts `value` as an `FheUint16`, serialized as the API expects.
pub fn encrypt(key: &ClientKey, value: u16) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    safe_serialize(
        &FheUint16::encrypt(value, key),
        &mut bytes,
        MAX_CIPHERTEXT_BYTES,
    )
    .map_err(|e| Error::Encoding(format!("serializing a ciphertext: {e}")))?;
    Ok(bytes)
}

/// Decrypts a serialized `FheUint16`, e.g. a job result. Ciphertexts that do
/// not match the key's parameters are refused rather than decrypted to noise.
pub fn decrypt(key: &ClientKey, bytes: &[u8]) -> Result<u16> {
    let conformance = FheUint16ConformanceParams::from(key.computation_parameters());
    let ciphertext: FheUint16 =
        safe_deserialize_conformant(bytes, MAX_CIPHERTEXT_BYTES, &conformance)
            .map_err(|e| Error::Encoding(format!("not a ciphertext for this key: {e}")))?;
    Ok(ciphertext.decrypt(key))
}

/// Writes `bytes` to `path` readable by its owner only (on Unix), replacing
/// any existing file atomically.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let name = path
        .file_name()
        .ok_or_else(|| Error::Encoding(format!("{} is not a file path", path.display())))?;
    let tmp = dir.unwrap_or(Path::new(".")).join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(written?)
}

pub fn save_client_key(path: &Path, key: &ClientKey) -> Result<()> {
    write_private(path, &client_key_bytes(key)?)
}

pub fn load_client_key(path: &Path) -> Result<ClientKey> {
    client_key_from_bytes(&std::fs::read(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// Client keys are cheap (no server key), so tests make their own.
    fn key() -> &'static ClientKey {
        static KEY: OnceLock<ClientKey> = OnceLock::new();
        KEY.get_or_init(|| ClientKey::generate(tfhe_config()))
    }

    #[test]
    fn encrypt_decrypt_round_trip_and_foreign_bytes_are_refused() {
        let bytes = encrypt(key(), 54321).unwrap();
        assert_eq!(decrypt(key(), &bytes).unwrap(), 54321);
        assert!(matches!(
            decrypt(key(), &bytes[..bytes.len() / 2]),
            Err(Error::Encoding(_))
        ));
        assert!(matches!(
            decrypt(key(), b"nonsense"),
            Err(Error::Encoding(_))
        ));
    }

    #[test]
    fn client_keys_are_saved_privately_and_load_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.key");
        save_client_key(&path, key()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let loaded = load_client_key(&path).unwrap();
        let bytes = encrypt(&loaded, 7).unwrap();
        assert_eq!(decrypt(key(), &bytes).unwrap(), 7);

        // Saving again replaces the file; no temporary files are left behind.
        save_client_key(&path, key()).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(load_client_key(&dir.path().join("missing")).is_err());
    }
}
