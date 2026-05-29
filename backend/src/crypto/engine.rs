use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tfhe::integer::{gen_keys_radix, RadixClientKey, ServerKey, RadixCiphertext};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

pub const NUM_BLOCKS: usize = 8;
pub const PLAIN_MODULUS: u64 = 1u64 << 16; // 65536

pub struct HeContext {
    client_key: RadixClientKey,
    server_key: ServerKey,
}

impl HeContext {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUM_BLOCKS);
        Ok(HeContext { client_key, server_key })
    }

    pub fn encrypt(&self, value: u64) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let ct: RadixCiphertext = self.client_key.encrypt(value);
        Ok(bincode::serialize(&ct)?)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let ct: RadixCiphertext = bincode::deserialize(data)?;
        Ok(self.client_key.decrypt(&ct))
    }

    pub fn add_ciphertexts(
        &self,
        ct1_bytes: &[u8],
        ct2_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let ct1: RadixCiphertext = bincode::deserialize(ct1_bytes)?;
        let ct2: RadixCiphertext = bincode::deserialize(ct2_bytes)?;
        let result = self.server_key.unchecked_add(&ct1, &ct2);
        Ok(bincode::serialize(&result)?)
    }

    pub fn multiply_ciphertexts(
        &self,
        ct1_bytes: &[u8],
        ct2_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let ct1: RadixCiphertext = bincode::deserialize(ct1_bytes)?;
        let ct2: RadixCiphertext = bincode::deserialize(ct2_bytes)?;
        let result = self.server_key.unchecked_mul(&ct1, &ct2);
        Ok(bincode::serialize(&result)?)
    }
}

pub struct HeContextPool {
    contexts: Vec<Arc<Mutex<HeContext>>>,
    counter: AtomicUsize,
}

impl HeContextPool {
    pub fn new(size: usize) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Generating {} TFHE-rs key pair(s) — this takes 10-60 s per slot…", size);
        let contexts = (0..size)
            .map(|i| {
                log::info!("  Generating key pair {}/{}…", i + 1, size);
                let ctx = HeContext::new()?;
                Ok(Arc::new(Mutex::new(ctx)))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>>>()?;
        log::info!("TFHE-rs key pool ready ({} slot(s))", size);
        Ok(HeContextPool { contexts, counter: AtomicUsize::new(0) })
    }

    pub fn acquire(&self) -> Arc<Mutex<HeContext>> {
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.contexts.len();
        self.contexts[idx].clone()
    }
}

pub struct AppState {
    pub he_pool: Arc<HeContextPool>,
}
