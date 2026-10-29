//! Local TFHE operations: key generation, encryption and decryption. Nothing
//! here talks to the server; the client key never leaves this process unless
//! you save it.

use crate::error::{Error, Result};
use heaas_core::params::{
    proof_metadata, tfhe_config, MAX_CIPHERTEXT_BYTES, MAX_CLIENT_KEY_BYTES, MAX_CRS_BYTES,
    MAX_PROVEN_LIST_BYTES, MAX_PUBLIC_KEY_BYTES, MAX_SERVER_KEY_BYTES,
};
use heaas_core::{IntegerType, PlainValue, ValueType};
use std::io::Write;
use std::path::Path;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_deserialize_conformant, safe_serialize};
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tfhe::{ClientKey, CompactCiphertextList, CompactPublicKey, CompressedServerKey};

pub use tfhe::ClientKey as SecretKey;

/// Runs `$body` with `$fhe` and `$clear` naming the TFHE-rs and Rust types of `$ty`.
macro_rules! per_type {
    ($ty:expr, $fhe:ident, $clear:ident, $conformance:ident => $body:expr) => {
        match $ty {
            IntegerType::U8 => {
                type $fhe = tfhe::FheUint8;
                type $clear = u8;
                type $conformance = tfhe::FheUint8ConformanceParams;
                $body
            }
            IntegerType::U16 => {
                type $fhe = tfhe::FheUint16;
                type $clear = u16;
                type $conformance = tfhe::FheUint16ConformanceParams;
                $body
            }
            IntegerType::U32 => {
                type $fhe = tfhe::FheUint32;
                type $clear = u32;
                type $conformance = tfhe::FheUint32ConformanceParams;
                $body
            }
            IntegerType::U64 => {
                type $fhe = tfhe::FheUint64;
                type $clear = u64;
                type $conformance = tfhe::FheUint64ConformanceParams;
                $body
            }
            IntegerType::I8 => {
                type $fhe = tfhe::FheInt8;
                type $clear = i8;
                type $conformance = tfhe::FheInt8ConformanceParams;
                $body
            }
            IntegerType::I16 => {
                type $fhe = tfhe::FheInt16;
                type $clear = i16;
                type $conformance = tfhe::FheInt16ConformanceParams;
                $body
            }
            IntegerType::I32 => {
                type $fhe = tfhe::FheInt32;
                type $clear = i32;
                type $conformance = tfhe::FheInt32ConformanceParams;
                $body
            }
            IntegerType::I64 => {
                type $fhe = tfhe::FheInt64;
                type $clear = i64;
                type $conformance = tfhe::FheInt64ConformanceParams;
                $body
            }
        }
    };
}

fn out_of_range(ty: IntegerType, value: i128) -> Error {
    Error::Encoding(format!(
        "{value} is outside the {ty} range ({} to {})",
        ty.min_value(),
        ty.max_value()
    ))
}

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

/// The compact public key proven inputs are encrypted under. Upload it with
/// [`crate::Client::upload_public_key`].
pub fn public_key(key: &ClientKey) -> CompactPublicKey {
    CompactPublicKey::new(key)
}

pub fn public_key_bytes(key: &CompactPublicKey) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    safe_serialize(key, &mut bytes, MAX_PUBLIC_KEY_BYTES)
        .map_err(|e| Error::Encoding(format!("serializing the public key: {e}")))?;
    Ok(bytes)
}

pub fn public_key_from_bytes(bytes: &[u8]) -> Result<CompactPublicKey> {
    safe_deserialize(bytes, MAX_PUBLIC_KEY_BYTES)
        .map_err(|e| Error::Encoding(format!("not a TFHE-rs compact public key: {e}")))
}

/// Encrypts `value` as a `u16` (`FheUint16`), serialized as the API expects.
pub fn encrypt(key: &ClientKey, value: u16) -> Result<Vec<u8>> {
    encrypt_as(key, IntegerType::U16, value.into())
}

/// Encrypts `value` as type `ty` (e.g. `i32` → `FheInt32`).
pub fn encrypt_as(key: &ClientKey, ty: IntegerType, value: i128) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    per_type!(ty, Fhe, Clear, _Conformance => {
        let clear = Clear::try_from(value).map_err(|_| out_of_range(ty, value))?;
        safe_serialize(&Fhe::encrypt(clear, key), &mut bytes, MAX_CIPHERTEXT_BYTES)
    })
    .map_err(|e| Error::Encoding(format!("serializing a ciphertext: {e}")))?;
    Ok(bytes)
}

/// Decrypts a serialized `FheUint16`, e.g. a job result. Ciphertexts that do
/// not match the key's parameters are refused rather than decrypted to noise.
pub fn decrypt(key: &ClientKey, bytes: &[u8]) -> Result<u16> {
    match decrypt_as(key, ValueType::U16, bytes)? {
        PlainValue::Int(v) => Ok(v as u16),
        PlainValue::Bool(_) => unreachable!("decrypted as u16"),
    }
}

/// Decrypts a serialized ciphertext of type `ty`, e.g. a job result of its
/// `result_type` (`bool` for comparisons).
pub fn decrypt_as(key: &ClientKey, ty: ValueType, bytes: &[u8]) -> Result<PlainValue> {
    let refused = |e: String| Error::Encoding(format!("not a {ty} ciphertext for this key: {e}"));
    let Some(ty) = ty.integer() else {
        let conformance = tfhe::FheBoolConformanceParams::from(key.computation_parameters());
        let ciphertext: tfhe::FheBool =
            safe_deserialize_conformant(bytes, MAX_CIPHERTEXT_BYTES, &conformance)
                .map_err(refused)?;
        return Ok(PlainValue::Bool(ciphertext.decrypt(key)));
    };
    per_type!(ty, Fhe, Clear, Conformance => {
        let conformance = Conformance::from(key.computation_parameters());
        let ciphertext: Fhe = safe_deserialize_conformant(bytes, MAX_CIPHERTEXT_BYTES, &conformance)
            .map_err(refused)?;
        let clear: Clear = ciphertext.decrypt(key);
        Ok(PlainValue::Int(clear as i128))
    })
}

/// Parses the CRS from `GET /api/v1/he/crs` (see [`crate::Client::crs`]).
pub fn crs_from_bytes(bytes: &[u8]) -> Result<CompactPkeCrs> {
    safe_deserialize(bytes, MAX_CRS_BYTES)
        .map_err(|e| Error::Encoding(format!("not a TFHE-rs CRS: {e}")))
}

/// Encrypts `values` (all of type `ty`) under `public_key` into one list with a
/// zero-knowledge proof, against the server's `crs`, that they are well-formed
/// encryptions. The proof is bound to `key_id`: send the list for that key as
/// `proven_inputs`. `public_key` must be the one uploaded for that key (each
/// [`public_key`] call makes a different one). Takes about a second.
pub fn prove(
    public_key: &CompactPublicKey,
    crs: &CompactPkeCrs,
    key_id: &str,
    ty: IntegerType,
    values: &[i128],
) -> Result<Vec<u8>> {
    let mut builder = CompactCiphertextList::builder(public_key);
    for &value in values {
        per_type!(ty, _Fhe, Clear, _Conformance => {
            builder.push(Clear::try_from(value).map_err(|_| out_of_range(ty, value))?);
        });
    }
    let list = builder
        .build_with_proof_packed(crs, &proof_metadata(key_id), ZkComputeLoad::Proof)
        .map_err(|e| Error::Encoding(format!("proving the inputs: {e}")))?;
    let mut bytes = Vec::new();
    safe_serialize(&list, &mut bytes, MAX_PROVEN_LIST_BYTES)
        .map_err(|e| Error::Encoding(format!("serializing the proven inputs: {e}")))?;
    Ok(bytes)
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
    fn every_type_round_trips_and_types_are_not_confused() {
        for ty in IntegerType::ALL {
            for value in [ty.min_value(), ty.max_value(), 0] {
                let bytes = encrypt_as(key(), ty, value).unwrap();
                assert_eq!(
                    decrypt_as(key(), ty.into(), &bytes).unwrap(),
                    PlainValue::Int(value)
                );
            }
            assert!(encrypt_as(key(), ty, ty.max_value() + 1).is_err());
        }
        let wide = encrypt_as(key(), IntegerType::U32, 7).unwrap();
        assert!(decrypt_as(key(), ValueType::U16, &wide).is_err());
        assert!(decrypt_as(key(), ValueType::Bool, &wide).is_err());
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
