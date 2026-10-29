//! The TFHE configuration HE Engine evaluates under.
//!
//! Clients generate their keys with the same configuration ([`tfhe_config`],
//! also what the browser uses), so the server can verify uploaded keys and
//! ciphertexts against it. It is TFHE-rs's default configuration plus Zama's
//! dedicated compact-public-key parameters, which let clients send
//! zero-knowledge-proven inputs.

use crate::types::IntegerType;
use tfhe::core_crypto::commons::math::random::DynamicDistribution;
use tfhe::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use tfhe::prelude::ParameterSetConformant;
use tfhe::shortint::parameters::{
    ClassicPBSParameters, CompactPublicKeyEncryptionParameters, ShortintKeySwitchingParameters,
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use tfhe::zk::CompactPkeCrs;
use tfhe::{CompressedServerKey, Config, ConfigBuilder};

/// TFHE-rs release keys and ciphertexts are made with. Clients must use the same
/// release: the serialization format is versioned. A test keeps this in sync
/// with `Cargo.lock` and the frontend's `tfhe` npm dependency.
pub const TFHE_VERSION: &str = "1.8.2";

/// The type a job computes on when the request does not say.
pub const DEFAULT_INTEGER_TYPE: IntegerType = IntegerType::U16;

/// Upper bound for one serialized ciphertext (`FheUint64` is ~530 KB with these
/// parameters, `FheUint16` ~130 KB). Enforced on deserialization so a crafted
/// length prefix cannot force unbounded allocations.
pub const MAX_CIPHERTEXT_BYTES: u64 = 1 << 20;

/// Most encrypted inputs one job takes (a `sum`).
pub const MAX_INPUTS: usize = 16;

/// Most input bytes one job takes: [`MAX_INPUTS`] `FheUint64`s fit.
pub const MAX_JOB_INPUT_BYTES: u64 = 9 << 20;

/// Upper bound for a serialized client (secret) key (~48 KB).
pub const MAX_CLIENT_KEY_BYTES: u64 = 1 << 26;

/// Upper bound when serializing a compressed server key (~60 MB). The server's
/// accepted upload size is configured separately (`MAX_SERVER_KEY_BYTES`).
pub const MAX_SERVER_KEY_BYTES: u64 = 1 << 30;

/// Upper bound for a serialized `CompactPublicKey` (~33 KB).
pub const MAX_PUBLIC_KEY_BYTES: u64 = 1 << 20;

/// Upper bound for a serialized `ProvenCompactCiphertextList` (~20 KB for any
/// list the CRS allows: inputs are packed).
pub const MAX_PROVEN_LIST_BYTES: u64 = 1 << 20;

/// Upper bound for the serialized CRS (~3.7 MB; ~1.9 MB compressed).
pub const MAX_CRS_BYTES: u64 = 1 << 26;

/// Most plaintext bits one proven list can hold: the CRS is generated for this
/// many (e.g. 8 × 64-bit or 32 × 16-bit inputs).
pub const MAX_PROVEN_BITS: usize = 512;

/// Parameters a `CompressedServerKey` must conform to. TFHE-rs does not export
/// the type by name, only through the trait.
pub type ServerKeyConformance = <CompressedServerKey as ParameterSetConformant>::ParameterSet;

/// The TFHE-rs parameter set `ConfigBuilder::default()` selects (CPU builds).
/// A test checks that the default really is this set.
pub const PARAMETER_SET: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub const PARAMETER_SET_NAME: &str = "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128";

/// Encryption under a client's compact public key, the form proven inputs take.
pub const PUBLIC_KEY_PARAMETERS: CompactPublicKeyEncryptionParameters =
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub const PUBLIC_KEY_PARAMETERS_NAME: &str = "PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128";

/// The key switch from public-key ciphertexts to [`PARAMETER_SET`] ciphertexts.
pub const CASTING_PARAMETERS: ShortintKeySwitchingParameters =
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub const CASTING_PARAMETERS_NAME: &str = "PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128";

/// The configuration keys are generated with.
pub fn tfhe_config() -> Config {
    ConfigBuilder::default()
        .use_dedicated_compact_public_key_parameters((PUBLIC_KEY_PARAMETERS, CASTING_PARAMETERS))
        .build()
}

/// `ConfigBuilder::default()` alone, which keys made before HE Engine 0.5 use.
/// Such keys still work but cannot take proven inputs (they lack the casting key).
pub fn legacy_tfhe_config() -> Config {
    ConfigBuilder::default().build()
}

pub fn server_key_conformance() -> ServerKeyConformance {
    ServerKeyConformance::from(tfhe_config())
}

pub fn legacy_server_key_conformance() -> ServerKeyConformance {
    ServerKeyConformance::from(legacy_tfhe_config())
}

/// A new CRS (common reference string) for proofs of [`MAX_PROVEN_BITS`] bits.
/// Takes several seconds; the server makes one and publishes it.
pub fn generate_crs() -> CompactPkeCrs {
    CompactPkeCrs::from_config(tfhe_config(), MAX_PROVEN_BITS)
        .expect("the configuration supports zero-knowledge proofs")
}

/// What a proven input list must conform to under `crs`.
pub fn proven_list_conformance(
    crs: &CompactPkeCrs,
) -> IntegerProvenCompactCiphertextListConformanceParams {
    IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(
        PUBLIC_KEY_PARAMETERS,
        crs,
    )
}

/// The metadata a proof of inputs for server key `key_id` is bound to, so a
/// proof made for one key is not accepted for another.
pub fn proof_metadata(key_id: &str) -> Vec<u8> {
    format!("he-engine/proof/v1/{key_id}").into_bytes()
}

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
    let (p, pk, ks) = (PARAMETER_SET, PUBLIC_KEY_PARAMETERS, CASTING_PARAMETERS);
    let rows = [
        ("TFHE-rs release", format!("`{TFHE_VERSION}`")),
        ("Parameter set", format!("`{PARAMETER_SET_NAME}`")),
        (
            "Encrypted types",
            IntegerType::ALL
                .iter()
                .map(|t| format!("`{}`", t.tfhe_name()))
                .collect::<Vec<_>>()
                .join(", ")
                + " (arithmetic modulo 2^bits) and `FheBool` (comparison results)",
        ),
        (
            "Blocks per integer",
            format!(
                "bits / {} (each block holds {} message bits and {} carry bits)",
                p.message_modulus.0.ilog2(),
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
            "Public-key encryption",
            format!(
                "`{PUBLIC_KEY_PARAMETERS_NAME}`: LWE dimension {}, {}, {:?}",
                pk.encryption_lwe_dimension.0,
                noise(pk.encryption_noise_distribution),
                pk.expansion_kind
            ),
        ),
        (
            "Casting key switch",
            format!(
                "`{CASTING_PARAMETERS_NAME}`: base log {}, level {}, to `{:?}`",
                ks.ks_base_log.0, ks.ks_level.0, ks.destination_key
            ),
        ),
        (
            "Zero-knowledge proofs",
            format!(
                "TFHE-rs compact PKE proofs (`{:?}`), CRS for {MAX_PROVEN_BITS} bits per list",
                pk.zk_scheme
            ),
        ),
        (
            "Size limits",
            format!(
                "ciphertext ≤ {MAX_CIPHERTEXT_BYTES} B, inputs per job ≤ {MAX_INPUTS} \
                 (≤ {MAX_JOB_INPUT_BYTES} B), proven list ≤ {MAX_PROVEN_LIST_BYTES} B, \
                 public key ≤ {MAX_PUBLIC_KEY_BYTES} B, client key ≤ {MAX_CLIENT_KEY_BYTES} B, \
                 compressed server key ≤ {MAX_SERVER_KEY_BYTES} B (servers may accept less)"
            ),
        ),
    ];
    let mut out = String::from(
        "<!-- Generated from core/src/params.rs by `UPDATE_DOCS=1 cargo test -p heaas-core`; do not edit. -->\n\
         # Cryptographic parameters\n\n\
         Every key and ciphertext HE Engine accepts is made with these parameters; servers\n\
         reject keys and ciphertexts that do not conform to them. They are TFHE-rs's\n\
         defaults and Zama's dedicated compact-public-key parameters for proven inputs,\n\
         which HE Engine does not tune. Zama states that its default parameters\n\
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
    fn both_configurations_compute_with_the_same_parameters() {
        assert_eq!(
            tfhe_config().public_key_encryption_parameters().unwrap(),
            PUBLIC_KEY_PARAMETERS
        );
        let legacy = tfhe::ClientKey::generate(legacy_tfhe_config());
        assert_eq!(
            legacy.computation_parameters(),
            tfhe::shortint::AtomicPatternParameters::from(PARAMETER_SET)
        );
        assert_ne!(proof_metadata("a"), proof_metadata("b"));
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
