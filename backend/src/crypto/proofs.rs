//! The CRS (common reference string) clients prove their inputs against.
//!
//! The server generates one on first start, keeps it next to the keys and
//! publishes it at `GET /api/v1/he/crs`. It is public: it lets anyone prove
//! that a ciphertext is a well-formed encryption, and lets the server check
//! such proofs.

use crate::crypto::params::{generate_crs, MAX_CRS_BYTES, MAX_PROVEN_BITS};
use crate::storage::write_atomic;
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::zk::{CompactPkeCrs, Compressible};

const CRS_FILE: &str = "crs.bin";

pub struct Crs {
    pub crs: CompactPkeCrs,
    /// What clients download: the compressed CRS, `safe_serialize`d. TFHE-rs
    /// decompresses it when deserializing as `CompactPkeCrs`.
    pub bytes: Vec<u8>,
    /// Lower-case hex SHA-256 of `bytes`.
    pub sha256: String,
}

impl Crs {
    fn from_bytes(bytes: Vec<u8>) -> io::Result<Self> {
        let crs: CompactPkeCrs = safe_deserialize(bytes.as_slice(), MAX_CRS_BYTES)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if crs.max_num_messages().0 == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty CRS"));
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        Ok(Crs { crs, bytes, sha256 })
    }

    /// Loads `<dir>/crs.bin`, generating and saving it first if there is none.
    /// Generation takes several seconds: call from a blocking thread.
    pub fn load_or_create(dir: &Path) -> io::Result<Self> {
        let path = dir.join(CRS_FILE);
        match std::fs::read(&path) {
            Ok(bytes) => Self::from_bytes(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                tracing::info!("Generating the proof CRS ({MAX_PROVEN_BITS} bits)");
                let mut bytes = Vec::new();
                safe_serialize(&generate_crs().compress(), &mut bytes, MAX_CRS_BYTES)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                write_atomic(&path, &bytes)?;
                Self::from_bytes(bytes)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::sync::{Arc, OnceLock};

    /// One CRS for all tests (generating one takes seconds).
    pub fn crs() -> Arc<Crs> {
        static CRS: OnceLock<Arc<Crs>> = OnceLock::new();
        CRS.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("heaas-crs-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let crs = Crs::load_or_create(&dir).unwrap();
            std::fs::remove_dir_all(dir).unwrap();
            Arc::new(crs)
        })
        .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_crs_is_reloaded_unchanged_and_corruption_is_refused() {
        // `test_support::crs()` went through generation; reload what it saved.
        let generated = test_support::crs();
        assert!(generated.bytes.len() < MAX_CRS_BYTES as usize);
        let dir = std::env::temp_dir().join(format!("heaas-crs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(CRS_FILE), &generated.bytes).unwrap();
        assert_eq!(Crs::load_or_create(&dir).unwrap().sha256, generated.sha256);

        std::fs::write(dir.join(CRS_FILE), b"corrupt").unwrap();
        assert!(Crs::load_or_create(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
