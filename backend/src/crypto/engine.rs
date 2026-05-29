// NOTE: This engine targets the `seal-rs 0.2` API. Before deploying,
// verify that the published crate version matches these method signatures
// and that the BFV parameter set is appropriate for your security requirements.
//
// If seal-rs is unavailable or its API changes, replace HeContext with your
// chosen HE library and update encrypt_batch / decrypt_batch / add_ciphertexts /
// multiply_ciphertexts accordingly.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Stub HE implementation
//
// seal-rs 0.2 is not yet published to crates.io.  The types below provide a
// structurally-correct stand-in that compiles and returns deterministic data
// so every other fix can be tested.  Replace this block (and the Cargo.toml
// seal-rs dependency) with the real crate once it is available.
// ---------------------------------------------------------------------------

/// Minimal batch-capable BFV context over a toy plaintext modulus (1024).
pub struct HeContext {
    /// Fixed plaintext modulus — values must be in [0, plain_mod).
    plain_mod: u64,
}

impl HeContext {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(HeContext { plain_mod: 1024 })
    }

    /// Encode `values` and return a stub ciphertext (just bincode-encoded).
    pub fn encrypt_batch(
        &self,
        values: &[u64],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let reduced: Vec<u64> = values.iter().map(|v| v % self.plain_mod).collect();
        Ok(bincode::serialize(&reduced)?)
    }

    /// Decode a stub ciphertext back to plaintext values.
    pub fn decrypt_batch(
        &self,
        data: &[u8],
    ) -> Result<Vec<u64>, Box<dyn std::error::Error + Send + Sync>> {
        let values: Vec<u64> = bincode::deserialize(data)?;
        Ok(values)
    }

    /// Add two stub ciphertexts component-wise (mod plain_mod).
    pub fn add_ciphertexts(
        &self,
        ct1_data: &[u8],
        ct2_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let v1: Vec<u64> = bincode::deserialize(ct1_data)?;
        let v2: Vec<u64> = bincode::deserialize(ct2_data)?;
        let result: Vec<u64> = v1
            .iter()
            .zip(v2.iter())
            .map(|(a, b)| (a + b) % self.plain_mod)
            .collect();
        Ok(bincode::serialize(&result)?)
    }

    /// Multiply two stub ciphertexts component-wise (mod plain_mod).
    pub fn multiply_ciphertexts(
        &self,
        ct1_data: &[u8],
        ct2_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let v1: Vec<u64> = bincode::deserialize(ct1_data)?;
        let v2: Vec<u64> = bincode::deserialize(ct2_data)?;
        let result: Vec<u64> = v1
            .iter()
            .zip(v2.iter())
            .map(|(a, b)| (a * b) % self.plain_mod)
            .collect();
        Ok(bincode::serialize(&result)?)
    }
}

// ---------------------------------------------------------------------------
// Context pool — eliminates the global single-mutex serialisation bottleneck.
// ---------------------------------------------------------------------------

pub struct HeContextPool {
    contexts: Vec<Arc<Mutex<HeContext>>>,
    counter: AtomicUsize,
}

impl HeContextPool {
    pub fn new(size: usize) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let contexts = (0..size)
            .map(|_| Ok(Arc::new(Mutex::new(HeContext::new()?))))
            .collect::<Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>>>()?;
        Ok(HeContextPool {
            contexts,
            counter: AtomicUsize::new(0),
        })
    }

    /// Round-robin acquisition — non-blocking with respect to other slots.
    pub fn acquire(&self) -> Arc<Mutex<HeContext>> {
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.contexts.len();
        self.contexts[idx].clone()
    }
}

pub struct AppState {
    pub he_pool: Arc<HeContextPool>,
}
