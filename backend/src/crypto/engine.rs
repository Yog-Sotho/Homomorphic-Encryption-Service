use seal_rs::{
    BatchEncoder, Encryptor, Evaluator, KeyGenerator, Plaintext, PublicKey, SecretKey,
    SerializationMode,
};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct HeContext {
    pub encoder: BatchEncoder,
    pub evaluator: Evaluator,
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl HeContext {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let context = seal_rs::SEALContext::create(
            seal_rs::EncryptionParameters::new(seal_rs::SchemeType::BFV)?
                .set_poly_modulus_degree(4096)?
                .set_plain_modulus(1024)?
                .set_coeff_modulus(seal_rs::CoeffModulus::bfv_default(4096, seal_rs::SecurityLevel::TC128)?)?,
        )?;

        let keygen = KeyGenerator::new(&context)?;
        let public_key = keygen.create_public_key()?;
        let secret_key = keygen.secret_key();
        
        let encoder = BatchEncoder::new(&context)?;
        let evaluator = Evaluator::new(&context)?;

        Ok(HeContext {
            encoder,
            evaluator,
            public_key,
            secret_key,
        })
    }

    pub fn encrypt_batch(&self, values: &[u64]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut plain = Plaintext::new()?;
        self.encoder.encode(values, &mut plain)?;
        
        let encryptor = Encryptor::new_with_pk(&self.public_key)?;
        let mut encrypted = seal_rs::Ciphertext::new()?;
        encryptor.encrypt(&plain, &mut encrypted)?;

        let mut buffer = Vec::new();
        encrypted.save(&mut buffer, SerializationMode::Compressed)?;
        Ok(buffer)
    }

    pub fn decrypt_batch(&self, data: &[u8]) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
        let mut encrypted = seal_rs::Ciphertext::new()?;
        encrypted.load(&self.evaluator.context(), data)?;

        let decryptor = seal_rs::Decryptor::new_with_sk(&self.secret_key)?;
        let mut plain = Plaintext::new()?;
        decryptor.decrypt(&encrypted, &mut plain)?;

        let mut decoded = vec![0u64; self.encoder.slot_count()];
        self.encoder.decode(&plain, &mut decoded)?;
        Ok(decoded)
    }

    pub fn add_ciphertexts(&self, ct1_ &[u8], ct2_ &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut ct1 = seal_rs::Ciphertext::new()?;
        let mut ct2 = seal_rs::Ciphertext::new()?;
        
        ct1.load(&self.evaluator.context(), ct1_data)?;
        ct2.load(&self.evaluator.context(), ct2_data)?;

        let mut result = seal_rs::Ciphertext::new()?;
        self.evaluator.add(&ct1, &ct2, &mut result)?;

        let mut buffer = Vec::new();
        result.save(&mut buffer, SerializationMode::Compressed)?;
        Ok(buffer)
    }

    pub fn multiply_ciphertexts(&self, ct1_ &[u8], ct2_ &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut ct1 = seal_rs::Ciphertext::new()?;
        let mut ct2 = seal_rs::Ciphertext::new()?;
        
        ct1.load(&self.evaluator.context(), ct1_data)?;
        ct2.load(&self.evaluator.context(), ct2_data)?;

        let mut result = seal_rs::Ciphertext::new()?;
        self.evaluator.multiply(&ct1, &ct2, &mut result)?;

        let mut buffer = Vec::new();
        result.save(&mut buffer, SerializationMode::Compressed)?;
        Ok(buffer)
    }
}

pub struct AppState {
    pub he_context: Arc<Mutex<HeContext>>,
}