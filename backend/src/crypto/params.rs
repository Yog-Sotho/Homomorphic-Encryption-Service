//! The one TFHE configuration this service evaluates under.
//!
//! Clients generate their keys with the same configuration (TFHE-rs
//! `ConfigBuilder::default()`, which is also what the browser SDK uses), so the
//! server can verify uploaded keys and ciphertexts against it.

use crate::config::Config as AppConfig;
use crate::crypto::eval::Operation;
use actix_web::{web, HttpResponse};
use serde::Serialize;
use std::sync::Arc;
use tfhe::prelude::ParameterSetConformant;
use tfhe::{CompressedServerKey, Config, ConfigBuilder};

/// TFHE-rs release the server is built with. Clients must use the same release:
/// the serialization format is versioned. A test keeps this in sync with
/// `Cargo.lock` and the frontend's `tfhe` npm dependency.
pub const TFHE_VERSION: &str = "1.8.2";

/// Encrypted values are `FheUint16`: arithmetic wraps modulo 2^16.
pub const INTEGER_TYPE: &str = "FheUint16";
pub const PLAIN_MODULUS: u64 = 1 << 16;

/// Upper bound for one serialized `FheUint16` (~130 KB with these parameters).
/// Enforced on deserialization so a crafted length prefix cannot make the server
/// allocate unbounded memory.
pub const MAX_CIPHERTEXT_BYTES: u64 = 1 << 20;

/// Parameters a `CompressedServerKey` must conform to. TFHE-rs does not export
/// the type by name, only through the trait.
pub(crate) type ServerKeyConformance =
    <CompressedServerKey as ParameterSetConformant>::ParameterSet;

pub fn tfhe_config() -> Config {
    ConfigBuilder::default().build()
}

pub(crate) fn server_key_conformance() -> ServerKeyConformance {
    ServerKeyConformance::from(tfhe_config())
}

#[derive(Serialize)]
pub struct HeParams {
    pub scheme: &'static str,
    pub library: &'static str,
    pub tfhe_version: &'static str,
    pub config: &'static str,
    pub integer_type: &'static str,
    pub plaintext_modulus: u64,
    pub operations: Vec<Operation>,
    pub max_ciphertext_bytes: u64,
    pub max_server_key_bytes: u64,
    pub max_keys_per_user: i64,
}

/// `GET /api/he/params` — what a client needs to produce compatible keys and inputs.
pub async fn get_params(config: web::Data<Arc<AppConfig>>) -> HttpResponse {
    HttpResponse::Ok().json(HeParams {
        scheme: "TFHE (CGGI)",
        library: "TFHE-rs",
        tfhe_version: TFHE_VERSION,
        config: "ConfigBuilder::default()",
        integer_type: INTEGER_TYPE,
        plaintext_modulus: PLAIN_MODULUS,
        operations: Operation::ALL.to_vec(),
        max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
        max_server_key_bytes: config.max_server_key_bytes,
        max_keys_per_user: config.max_keys_per_user,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Version of `name` as recorded in a Cargo.lock.
    fn locked_version<'a>(lock: &'a str, name: &str) -> &'a str {
        let header = format!("name = \"{name}\"\nversion = \"");
        let start = lock.find(&header).expect("crate in Cargo.lock") + header.len();
        let end = start + lock[start..].find('"').unwrap();
        &lock[start..end]
    }

    #[test]
    fn tfhe_version_matches_lockfile_and_browser_sdk() {
        let lock = include_str!("../../Cargo.lock");
        assert_eq!(
            locked_version(lock, "tfhe"),
            TFHE_VERSION,
            "update TFHE_VERSION"
        );

        // The browser encrypts with the npm build of the same release.
        let package: serde_json::Value =
            serde_json::from_str(include_str!("../../../frontend/package.json")).unwrap();
        assert_eq!(
            package["dependencies"]["tfhe"], TFHE_VERSION,
            "frontend tfhe must be pinned to the backend's release"
        );
    }
}
