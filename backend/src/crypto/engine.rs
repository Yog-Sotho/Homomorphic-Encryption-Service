use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize_conformant, safe_serialize};
use tfhe::{
    generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint16, FheUint16ConformanceParams,
    ServerKey,
};

/// Encrypted integers are 16-bit (`FheUint16`): arithmetic wraps modulo 2^16.
pub const PLAIN_MODULUS: u64 = 1u64 << 16; // 65536

/// Upper bound for one serialized `FheUint16`. Enforced on deserialization so a
/// crafted length prefix cannot make the server allocate unbounded memory.
pub const MAX_CIPHERTEXT_BYTES: u64 = 1 << 20;

type HeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct HeContext {
    client_key: ClientKey,
    server_key: ServerKey,
    conformance: FheUint16ConformanceParams,
}

fn serialize_ct(ct: &FheUint16) -> HeResult<Vec<u8>> {
    let mut buf = Vec::new();
    safe_serialize(ct, &mut buf, MAX_CIPHERTEXT_BYTES)?;
    Ok(buf)
}

impl HeContext {
    pub fn new() -> HeResult<Self> {
        let (client_key, server_key) = generate_keys(ConfigBuilder::default());
        let conformance = FheUint16ConformanceParams::from(&server_key);
        Ok(HeContext {
            client_key,
            server_key,
            conformance,
        })
    }

    /// Deserializes untrusted bytes, rejecting oversized input and ciphertexts whose
    /// type, parameters or block count do not match this context's server key.
    fn deserialize_ct(&self, bytes: &[u8]) -> HeResult<FheUint16> {
        safe_deserialize_conformant(bytes, MAX_CIPHERTEXT_BYTES, &self.conformance)
            .map_err(|e| format!("Invalid ciphertext: {}", e).into())
    }

    /// TFHE-rs evaluates high-level operators with a thread-local server key, and
    /// blocking-pool threads are reused, so the key is (re)installed per operation.
    /// `ServerKey` is reference-counted, so this is a cheap clone.
    fn install_server_key(&self) {
        set_server_key(self.server_key.clone());
    }

    #[allow(dead_code)]
    pub fn encrypt(&self, value: u64) -> HeResult<Vec<u8>> {
        let value = u16::try_from(value)?;
        serialize_ct(&FheUint16::try_encrypt(value, &self.client_key)?)
    }

    #[allow(dead_code)]
    pub fn decrypt(&self, data: &[u8]) -> HeResult<u64> {
        let value: u16 = self.deserialize_ct(data)?.decrypt(&self.client_key);
        Ok(value.into())
    }

    pub fn add_ciphertexts(&self, ct1_bytes: &[u8], ct2_bytes: &[u8]) -> HeResult<Vec<u8>> {
        let ct1 = self.deserialize_ct(ct1_bytes)?;
        let ct2 = self.deserialize_ct(ct2_bytes)?;
        self.install_server_key();
        serialize_ct(&(&ct1 + &ct2))
    }

    pub fn multiply_ciphertexts(&self, ct1_bytes: &[u8], ct2_bytes: &[u8]) -> HeResult<Vec<u8>> {
        let ct1 = self.deserialize_ct(ct1_bytes)?;
        let ct2 = self.deserialize_ct(ct2_bytes)?;
        self.install_server_key();
        serialize_ct(&(&ct1 * &ct2))
    }

    /// Optimized sandbox compute: encrypts, operates, and decrypts in a single pass.
    /// Avoids 5 serialization/deserialization cycles of large HE ciphertexts.
    pub fn sandbox_compute_optimized(
        &self,
        v1: u64,
        v2: u64,
        op: &str,
    ) -> HeResult<(u64, Vec<u8>)> {
        let ct1 = FheUint16::try_encrypt(u16::try_from(v1)?, &self.client_key)?;
        let ct2 = FheUint16::try_encrypt(u16::try_from(v2)?, &self.client_key)?;

        self.install_server_key();
        let result_ct = if op == "add" {
            &ct1 + &ct2
        } else {
            &ct1 * &ct2
        };

        let plaintext: u16 = result_ct.decrypt(&self.client_key);
        let result_bytes = serialize_ct(&result_ct)?;

        Ok((plaintext.into(), result_bytes))
    }
}

pub struct HeContextPool {
    pub(crate) contexts: Vec<Arc<HeContext>>,
    pub(crate) counter: AtomicUsize,
}

impl HeContextPool {
    pub async fn new(size: usize) -> HeResult<Self> {
        log::info!(
            "Generating {} TFHE-rs key pair(s) in parallel — this takes 10-60 s…",
            size
        );

        let mut handles = Vec::with_capacity(size);
        for i in 0..size {
            handles.push(tokio::task::spawn_blocking(move || {
                log::info!("  Generating key pair {}/{}…", i + 1, size);
                HeContext::new()
            }));
        }

        let mut contexts = Vec::with_capacity(size);
        for handle in handles {
            let ctx = handle.await??;
            contexts.push(Arc::new(ctx));
        }

        log::info!("TFHE-rs key pool ready ({} slot(s))", size);
        Ok(HeContextPool {
            contexts,
            counter: AtomicUsize::new(0),
        })
    }

    pub fn acquire(&self) -> Arc<HeContext> {
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.contexts.len();
        self.contexts[idx].clone()
    }
}

pub struct AppState {
    pub he_pool: Arc<HeContextPool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::FheUint8;

    #[test]
    fn he_roundtrip_and_untrusted_input_validation() {
        // Key generation is expensive, so all engine checks share one context.
        let ctx = HeContext::new().unwrap();

        let a = ctx.encrypt(40_000).unwrap();
        let b = ctx.encrypt(30_000).unwrap();
        assert!(
            a.len() as u64 <= MAX_CIPHERTEXT_BYTES,
            "ciphertext is {} bytes",
            a.len()
        );

        // Addition and multiplication wrap modulo 2^16 with carries propagated.
        let sum = ctx.add_ciphertexts(&a, &b).unwrap();
        assert_eq!(
            ctx.decrypt(&sum).unwrap(),
            (40_000 + 30_000) % PLAIN_MODULUS
        );
        let prod = ctx.multiply_ciphertexts(&a, &b).unwrap();
        assert_eq!(
            ctx.decrypt(&prod).unwrap(),
            (40_000u64 * 30_000) % PLAIN_MODULUS
        );

        // Results can be fed back in: chained operations stay correct.
        let chained = ctx.add_ciphertexts(&sum, &prod).unwrap();
        assert_eq!(
            ctx.decrypt(&chained).unwrap(),
            ((40_000 + 30_000) + 40_000u64 * 30_000) % PLAIN_MODULUS
        );

        let (plain, ct) = ctx.sandbox_compute_optimized(7, 6, "multiply").unwrap();
        assert_eq!(plain, 42);
        assert_eq!(ctx.decrypt(&ct).unwrap(), 42);

        // Out-of-range plaintexts are rejected rather than truncated.
        assert!(ctx.encrypt(PLAIN_MODULUS).is_err());

        // Untrusted bytes are rejected with an error, never a panic.
        assert!(ctx.add_ciphertexts(b"not a ciphertext", &b).is_err());
        assert!(ctx.add_ciphertexts(&a[..a.len() / 2], &b).is_err());
        assert!(ctx.add_ciphertexts(&[], &b).is_err());

        // A well-formed ciphertext of a different integer type is rejected too.
        let narrow = FheUint8::try_encrypt(1u8, &ctx.client_key).unwrap();
        let mut narrow_bytes = Vec::new();
        safe_serialize(&narrow, &mut narrow_bytes, MAX_CIPHERTEXT_BYTES).unwrap();
        assert!(ctx.add_ciphertexts(&narrow_bytes, &b).is_err());
    }
}
