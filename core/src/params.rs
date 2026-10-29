//! The one TFHE configuration HE Engine evaluates under.
//!
//! Clients generate their keys with the same configuration (TFHE-rs
//! `ConfigBuilder::default()`, which is also what the browser uses), so the
//! server can verify uploaded keys and ciphertexts against it.

use tfhe::core_crypto::commons::math::random::DynamicDistribution;
use tfhe::prelude::ParameterSetConformant;
use tfhe::shortint::parameters::{
    ClassicPBSParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
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

/// The TFHE-rs parameter set `ConfigBuilder::default()` selects (CPU builds).
/// A test checks that the default really is this set.
pub const PARAMETER_SET: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub const PARAMETER_SET_NAME: &str = "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128";

fn noise(distribution: DynamicDistribution<u64>) -> String {
    match distribution {
        DynamicDistribution::TUniform(t) => {
            format!("TUniform, bound 2^{}", t.bound_log2())
        }
        DynamicDistribution::Gaussian(g) => format!("Gaussian, σ = {:e}", g.std),
    }
}

/// `docs/parameters.md`: the cryptographic parameters, generated from
/// [`PARAMETER_SET`] so the document cannot drift from the code.
pub fn parameter_sheet() -> String {
    let p = PARAMETER_SET;
    let rows = [
        ("TFHE-rs release", format!("`{TFHE_VERSION}`")),
        ("Parameter set", format!("`{PARAMETER_SET_NAME}`")),
        (
            "Encrypted type",
            format!("`{INTEGER_TYPE}` (plaintexts modulo {PLAIN_MODULUS})"),
        ),
        (
            "Blocks per integer",
            format!(
                "{} (each block holds {} message bits and {} carry bits)",
                16 / p.message_modulus.0.ilog2(),
                p.message_modulus.0.ilog2(),
                p.carry_modulus.0.ilog2()
            ),
        ),
        (
            "Failure probability per PBS",
            format!("2^{:.3}", p.log2_p_fail),
        ),
        ("LWE dimension *n*", p.lwe_dimension.0.to_string()),
        ("GLWE dimension *k*", p.glwe_dimension.0.to_string()),
        ("Polynomial size *N*", p.polynomial_size.0.to_string()),
        ("LWE noise", noise(p.lwe_noise_distribution)),
        ("GLWE noise", noise(p.glwe_noise_distribution)),
        (
            "PBS decomposition",
            format!("base log {}, level {}", p.pbs_base_log.0, p.pbs_level.0),
        ),
        (
            "Key-switch decomposition",
            format!("base log {}, level {}", p.ks_base_log.0, p.ks_level.0),
        ),
        (
            "Ciphertext modulus",
            format!("`{:?}`", p.ciphertext_modulus),
        ),
        ("Encryption key", format!("`{:?}`", p.encryption_key_choice)),
        (
            "Size limits",
            format!(
                "ciphertext ≤ {MAX_CIPHERTEXT_BYTES} B, client key ≤ {MAX_CLIENT_KEY_BYTES} B, \
                 compressed server key ≤ {MAX_SERVER_KEY_BYTES} B (servers may accept less)"
            ),
        ),
    ];
    let mut out = String::from(
        "<!-- Generated from core/src/params.rs by `UPDATE_DOCS=1 cargo test -p heaas-core`; do not edit. -->\n\
         # Cryptographic parameters\n\n\
         Every key and ciphertext HE Engine accepts is made with these parameters; servers\n\
         reject keys and ciphertexts that do not conform to them. They are TFHE-rs's\n\
         defaults, which HE Engine does not tune. Zama states that its default parameters\n\
         give at least 128 bits of security (Lattice Estimator, MATZOV cost model) with\n\
         a bootstrapping failure probability of at most 2^-128, chosen for the IND-CPA^D\n\
         model: see [Security and cryptography](https://docs.zama.org/tfhe-rs/get-started/security-and-cryptography).\n\n\
         | | |\n|---|---|\n",
    );
    for (name, value) in rows {
        out.push_str(&format!("| {name} | {value} |\n"));
    }
    out
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
    fn the_default_configuration_is_the_documented_parameter_set() {
        let key = tfhe::ClientKey::generate(tfhe_config());
        assert_eq!(
            key.computation_parameters(),
            tfhe::shortint::AtomicPatternParameters::from(PARAMETER_SET)
        );
    }

    #[test]
    fn the_parameter_sheet_is_current() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/parameters.md");
        if std::env::var_os("UPDATE_DOCS").is_some() {
            std::fs::write(path, parameter_sheet()).unwrap();
            return;
        }
        let on_disk = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            on_disk == parameter_sheet(),
            "docs/parameters.md is out of date; regenerate it with `UPDATE_DOCS=1 cargo test -p heaas-core`"
        );
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
