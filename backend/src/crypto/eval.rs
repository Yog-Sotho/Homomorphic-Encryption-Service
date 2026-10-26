//! Homomorphic evaluation under a user's own server key.
//!
//! The server never holds a client (secret) key: it deserializes the caller's
//! ciphertexts, checks they conform to the caller's key, computes, and returns an
//! encrypted result only the caller can decrypt.

use crate::crypto::keys::UserServerKey;
use crate::crypto::params::MAX_CIPHERTEXT_BYTES;
use serde::{Deserialize, Serialize};
use std::fmt;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize_conformant, safe_serialize};
use tfhe::{set_server_key, FheUint16};

/// Binary operations on `FheUint16`. Arithmetic wraps modulo 2^16.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Add,
    Subtract,
    Multiply,
    Min,
    Max,
}

impl Operation {
    pub const ALL: [Operation; 5] = [
        Operation::Add,
        Operation::Subtract,
        Operation::Multiply,
        Operation::Min,
        Operation::Max,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Add => "add",
            Operation::Subtract => "subtract",
            Operation::Multiply => "multiply",
            Operation::Min => "min",
            Operation::Max => "max",
        }
    }

    /// Plaintext reference semantics, used by tests and clients to check results.
    #[cfg(test)]
    pub fn apply_plain(self, a: u16, b: u16) -> u16 {
        match self {
            Operation::Add => a.wrapping_add(b),
            Operation::Subtract => a.wrapping_sub(b),
            Operation::Multiply => a.wrapping_mul(b),
            Operation::Min => a.min(b),
            Operation::Max => a.max(b),
        }
    }
}

#[derive(Debug)]
pub enum EvalError {
    /// The caller's input is unusable; the message is safe to show them.
    InvalidInput(String),
    /// Server-side failure; details are logged, not returned.
    Internal(String),
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalError::InvalidInput(m) | EvalError::Internal(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for EvalError {}

fn deserialize_input(
    key: &UserServerKey,
    bytes: &[u8],
    which: usize,
) -> Result<FheUint16, EvalError> {
    safe_deserialize_conformant(bytes, MAX_CIPHERTEXT_BYTES, &key.ciphertext_conformance).map_err(
        |_| {
            EvalError::InvalidInput(format!(
                "Input {which} is not a valid FheUint16 ciphertext for this key"
            ))
        },
    )
}

/// Evaluates `op` on two serialized `FheUint16` ciphertexts. CPU-heavy: call from
/// a blocking thread.
pub fn evaluate(
    key: &UserServerKey,
    op: Operation,
    lhs: &[u8],
    rhs: &[u8],
) -> Result<Vec<u8>, EvalError> {
    let a = deserialize_input(key, lhs, 1)?;
    let b = deserialize_input(key, rhs, 2)?;

    // TFHE-rs evaluates with a thread-local server key and blocking-pool threads
    // are reused, so install this caller's key for every evaluation. `ServerKey`
    // is reference-counted: the clone is cheap.
    set_server_key(key.server_key.clone());
    let result = match op {
        Operation::Add => &a + &b,
        Operation::Subtract => &a - &b,
        Operation::Multiply => &a * &b,
        Operation::Min => a.min(&b),
        Operation::Max => a.max(&b),
    };

    let mut out = Vec::new();
    safe_serialize(&result, &mut out, MAX_CIPHERTEXT_BYTES)
        .map_err(|e| EvalError::Internal(format!("serializing result: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::test_support::{client_key, user_server_key};
    use tfhe::{ClientKey, FheUint8};

    fn encrypt(ck: &ClientKey, value: u16) -> Vec<u8> {
        let mut out = Vec::new();
        safe_serialize(
            &FheUint16::encrypt(value, ck),
            &mut out,
            MAX_CIPHERTEXT_BYTES,
        )
        .unwrap();
        out
    }

    fn decrypt(ck: &ClientKey, bytes: &[u8]) -> u16 {
        let ct: FheUint16 =
            tfhe::safe_serialization::safe_deserialize(bytes, MAX_CIPHERTEXT_BYTES).unwrap();
        ct.decrypt(ck)
    }

    #[test]
    fn every_operation_matches_plaintext_semantics() {
        let ck = client_key();
        let key = user_server_key();
        // Includes wrap-around (overflow and underflow) and equal operands.
        let cases = [(40_000u16, 30_000u16), (7, 9), (u16::MAX, 1), (0, 0)];
        for op in Operation::ALL {
            for (a, b) in cases {
                let out = evaluate(&key, op, &encrypt(ck, a), &encrypt(ck, b)).unwrap();
                assert_eq!(decrypt(ck, &out), op.apply_plain(a, b), "{op:?}({a}, {b})");
            }
        }
    }

    #[test]
    fn results_can_be_fed_back_as_inputs() {
        let ck = client_key();
        let key = user_server_key();
        let sum = evaluate(
            &key,
            Operation::Add,
            &encrypt(ck, 1_000),
            &encrypt(ck, 2_000),
        )
        .unwrap();
        let product = evaluate(&key, Operation::Multiply, &sum, &encrypt(ck, 3)).unwrap();
        assert_eq!(decrypt(ck, &product), 9_000);
    }

    #[test]
    fn rejects_malformed_and_foreign_ciphertexts_without_panicking() {
        let ck = client_key();
        let key = user_server_key();
        let good = encrypt(ck, 5);

        let truncated = &good[..good.len() / 2];
        for bad in [b"not a ciphertext".as_slice(), truncated, &[]] {
            let err = evaluate(&key, Operation::Add, bad, &good).unwrap_err();
            assert!(matches!(err, EvalError::InvalidInput(_)), "{err}");
        }

        // A well-formed ciphertext of another integer type.
        let mut narrow = Vec::new();
        safe_serialize(
            &FheUint8::encrypt(1u8, ck),
            &mut narrow,
            MAX_CIPHERTEXT_BYTES,
        )
        .unwrap();
        assert!(matches!(
            evaluate(&key, Operation::Add, &good, &narrow),
            Err(EvalError::InvalidInput(_))
        ));
    }

    #[test]
    fn operation_names_round_trip() {
        for op in Operation::ALL {
            assert_eq!(serde_json::to_value(op).unwrap(), op.as_str());
            assert_eq!(
                serde_json::from_value::<Operation>(op.as_str().into()).unwrap(),
                op
            );
        }
        assert!(serde_json::from_value::<Operation>("divide".into()).is_err());
    }
}
