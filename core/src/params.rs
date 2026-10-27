//! The one TFHE configuration HEaaS evaluates under.
//!
//! Clients generate their keys with the same configuration (TFHE-rs
//! `ConfigBuilder::default()`, which is also what the browser uses), so the
//! server can verify uploaded keys and ciphertexts against it.

use tfhe::prelude::ParameterSetConformant;
use tfhe::{CompressedServerKey, Config, ConfigBuilder};

/// TFHE-rs release keys and ciphertexts are made with. Clients must use the same
/// release: the serialization format is versioned. A test keeps this in sync
/// with `Cargo.lock` and the frontend's `tfhe` npm dependency.
pub const TFHE_VERSION: &str = "1.8.2";

/// Encrypted values are `FheUint16`: arithmetic wraps modulo 2^16.
pub const INTEGER_TYPE: &str = "FheUint16";
pub const PLAIN_MODULUS: u64 = 1 << 16;

/// Upper bound for one serialized `FheUint16` (~130 KB with these parameters).
/// Enforced on deserialization so a crafted length prefix cannot force
/// unbounded allocations.
pub const MAX_CIPHERTEXT_BYTES: u64 = 1 << 20;

/// Upper bound for a serialized client (secret) key (~31 KB).
pub const MAX_CLIENT_KEY_BYTES: u64 = 1 << 26;

/// Upper bound when serializing a compressed server key (~60 MB). The server's
/// accepted upload size is configured separately (`MAX_SERVER_KEY_BYTES`).
pub const MAX_SERVER_KEY_BYTES: u64 = 1 << 30;

/// Parameters a `CompressedServerKey` must conform to. TFHE-rs does not export
/// the type by name, only through the trait.
pub type ServerKeyConformance = <CompressedServerKey as ParameterSetConformant>::ParameterSet;

pub fn tfhe_config() -> Config {
    ConfigBuilder::default().build()
}

pub fn server_key_conformance() -> ServerKeyConformance {
    ServerKeyConformance::from(tfhe_config())
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
            serde_json::from_str(include_str!("../../frontend/package.json")).unwrap();
        assert_eq!(
            package["dependencies"]["tfhe"], TFHE_VERSION,
            "frontend tfhe must be pinned to the server's release"
        );
    }
}
