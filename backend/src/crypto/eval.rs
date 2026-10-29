//! Homomorphic evaluation under a user's own server key.
//!
//! The server never holds a client (secret) key: it deserializes the caller's
//! ciphertexts, checks they conform to the caller's key (and, for proven inputs,
//! that their zero-knowledge proof verifies), computes, and returns an encrypted
//! result only the caller can decrypt.

use crate::crypto::keys::UserServerKey;
use crate::crypto::params::{proven_list_conformance, MAX_CIPHERTEXT_BYTES, MAX_PROVEN_LIST_BYTES};
use std::fmt;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize_conformant, safe_serialize};
use tfhe::zk::CompactPkeCrs;
use tfhe::{
    set_server_key, CompactPublicKey, FheBool, FheBoolConformanceParams, FheTypes,
    ProvenCompactCiphertextList,
};

pub use heaas_core::{IntegerType, Operation};

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

fn invalid(message: impl Into<String>) -> EvalError {
    EvalError::InvalidInput(message.into())
}

/// What a proof of inputs is checked against.
pub struct ProofContext<'a> {
    pub crs: &'a CompactPkeCrs,
    /// The key owner's compact public key, which the inputs are encrypted under.
    pub public_key: &'a CompactPublicKey,
    /// [`proof_metadata`](crate::crypto::params::proof_metadata) of the key.
    pub metadata: &'a [u8],
}

pub enum Inputs<'a> {
    /// One serialized ciphertext per input.
    Ciphertexts(&'a [Vec<u8>]),
    /// One serialized `ProvenCompactCiphertextList` holding every input.
    Proven {
        list: &'a [u8],
        proof: ProofContext<'a>,
    },
}

pub struct Job<'a> {
    pub operation: Operation,
    pub integer_type: IntegerType,
    /// The plaintext right-hand operand, already in `integer_type`'s range.
    pub scalar: Option<i128>,
    pub inputs: Inputs<'a>,
}

fn kind_of(ty: IntegerType) -> FheTypes {
    match ty {
        IntegerType::U8 => FheTypes::Uint8,
        IntegerType::U16 => FheTypes::Uint16,
        IntegerType::U32 => FheTypes::Uint32,
        IntegerType::U64 => FheTypes::Uint64,
        IntegerType::I8 => FheTypes::Int8,
        IntegerType::I16 => FheTypes::Int16,
        IntegerType::I32 => FheTypes::Int32,
        IntegerType::I64 => FheTypes::Int64,
    }
}

fn deserialize_list(
    bytes: &[u8],
    crs: &CompactPkeCrs,
) -> Result<ProvenCompactCiphertextList, EvalError> {
    safe_deserialize_conformant(bytes, MAX_PROVEN_LIST_BYTES, &proven_list_conformance(crs))
        .map_err(|_| {
            invalid(
                "The proven inputs are not a valid proven ciphertext list for this server's CRS",
            )
        })
}

/// Checks a proven input list without verifying its proof (cheap, for request
/// validation) and returns how many inputs it holds. Every input must be of
/// type `ty`.
pub fn proven_input_count(
    bytes: &[u8],
    crs: &CompactPkeCrs,
    ty: IntegerType,
) -> Result<usize, EvalError> {
    let list = deserialize_list(bytes, crs)?;
    let expected = kind_of(ty);
    for i in 0..list.len() {
        if list.get_kind_of(i) != Some(expected) {
            return Err(invalid(format!(
                "Proven input {} is not a {}",
                i + 1,
                ty.tfhe_name()
            )));
        }
    }
    Ok(list.len())
}

/// A computed result, before it is made conformant and serialized.
enum Output<T> {
    Int(T),
    Bool(FheBool),
}

/// `op(a, b)` where `b` is a ciphertext reference or a clear scalar.
macro_rules! apply {
    ($op:expr, $a:expr, $b:expr) => {
        match $op {
            Operation::Add => Output::Int($a + $b),
            Operation::Subtract => Output::Int($a - $b),
            Operation::Multiply => Output::Int($a * $b),
            Operation::Min => Output::Int($a.min($b)),
            Operation::Max => Output::Int($a.max($b)),
            Operation::Eq => Output::Bool($a.eq($b)),
            Operation::Ne => Output::Bool($a.ne($b)),
            Operation::Lt => Output::Bool($a.lt($b)),
            Operation::Le => Output::Bool($a.le($b)),
            Operation::Gt => Output::Bool($a.gt($b)),
            Operation::Ge => Output::Bool($a.ge($b)),
            Operation::Sum => unreachable!("sum is not a binary operation"),
        }
    };
}

macro_rules! serialize {
    ($value:expr) => {{
        let mut out = Vec::new();
        safe_serialize(&$value, &mut out, MAX_CIPHERTEXT_BYTES)
            .map_err(|e| EvalError::Internal(format!("serializing result: {e}")))?;
        Ok(out)
    }};
}

/// An evaluator for one concrete TFHE-rs type.
macro_rules! typed_evaluator {
    ($name:ident, $fhe:ty, $clear:ty, $conformance:ty) => {
        fn $name(key: &UserServerKey, job: &Job) -> Result<Vec<u8>, EvalError> {
            let tfhe_name = job.integer_type.tfhe_name();
            let values: Vec<$fhe> = match &job.inputs {
                Inputs::Ciphertexts(raw) => {
                    let conformance = <$conformance>::from(&key.server_key);
                    raw.iter()
                        .enumerate()
                        .map(|(i, bytes)| {
                            safe_deserialize_conformant(
                                bytes.as_slice(),
                                MAX_CIPHERTEXT_BYTES,
                                &conformance,
                            )
                            .map_err(|_| {
                                invalid(format!(
                                    "Input {} is not a valid {tfhe_name} ciphertext for this key",
                                    i + 1
                                ))
                            })
                        })
                        .collect::<Result<_, _>>()?
                }
                Inputs::Proven { list, proof } => {
                    if !key.supports_proofs {
                        return Err(invalid(
                            "This server key was made without the compact-public-key \
                             parameters and cannot take proven inputs",
                        ));
                    }
                    let list = deserialize_list(list, proof.crs)?;
                    // Expanding casts the inputs with the server key's casting key.
                    set_server_key(key.server_key.clone());
                    let expander = list
                        .verify_and_expand(proof.crs, proof.public_key, proof.metadata)
                        .map_err(|_| {
                            invalid("The proof of the inputs does not verify for this key")
                        })?;
                    (0..list.len())
                        .map(|i| match expander.get::<$fhe>(i) {
                            Ok(Some(value)) => Ok(value),
                            _ => Err(invalid(format!("Proven input {} is not a {tfhe_name}", i + 1))),
                        })
                        .collect::<Result<_, _>>()?
                }
            };
            job.operation
                .check_operands(values.len(), job.scalar.is_some())
                .map_err(EvalError::InvalidInput)?;

            // TFHE-rs evaluates with a thread-local server key and blocking-pool
            // threads are reused, so install this caller's key for every
            // evaluation. `ServerKey` is reference-counted: the clone is cheap.
            set_server_key(key.server_key.clone());
            let output = match (job.operation, job.scalar) {
                (Operation::Sum, _) => Output::Int(values.iter().sum::<$fhe>()),
                (op, Some(scalar)) => {
                    let scalar = <$clear>::try_from(scalar).map_err(|_| {
                        invalid(format!("The scalar is outside the {} range", job.integer_type))
                    })?;
                    apply!(op, &values[0], scalar)
                }
                (op, None) => apply!(op, &values[0], &values[1]),
            };

            // Results must be ciphertexts clients (and later jobs) accept as
            // conformant. With a scalar, TFHE-rs leaves parts it can compute
            // without the inputs (e.g. `x * 0`, the low blocks of `x * 4`,
            // `x < 0` unsigned) as trivial, unencrypted blocks; mixing in an
            // encryption of zero (or false) derived from an input fixes them.
            let input = &values[0];
            match output {
                Output::Int(mut result) => {
                    let conformance = <$conformance>::from(&key.server_key);
                    if !result.is_conformant(&conformance) {
                        let zero = input - input;
                        result = &result + &zero;
                    }
                    if !result.is_conformant(&conformance) {
                        return Err(EvalError::Internal("result is not conformant".into()));
                    }
                    serialize!(result)
                }
                Output::Bool(mut result) => {
                    let conformance = FheBoolConformanceParams::from(&key.server_key);
                    if !result.is_conformant(&conformance) {
                        let known = result.try_decrypt_trivial().map_err(|_| {
                            EvalError::Internal("non-conformant boolean result".into())
                        })?;
                        let fresh_false = input.ne(input);
                        result = if known { !fresh_false } else { fresh_false };
                    }
                    if !result.is_conformant(&conformance) {
                        return Err(EvalError::Internal("result is not conformant".into()));
                    }
                    serialize!(result)
                }
            }
        }
    };
}

typed_evaluator!(eval_u8, tfhe::FheUint8, u8, tfhe::FheUint8ConformanceParams);
typed_evaluator!(
    eval_u16,
    tfhe::FheUint16,
    u16,
    tfhe::FheUint16ConformanceParams
);
typed_evaluator!(
    eval_u32,
    tfhe::FheUint32,
    u32,
    tfhe::FheUint32ConformanceParams
);
typed_evaluator!(
    eval_u64,
    tfhe::FheUint64,
    u64,
    tfhe::FheUint64ConformanceParams
);
typed_evaluator!(eval_i8, tfhe::FheInt8, i8, tfhe::FheInt8ConformanceParams);
typed_evaluator!(
    eval_i16,
    tfhe::FheInt16,
    i16,
    tfhe::FheInt16ConformanceParams
);
typed_evaluator!(
    eval_i32,
    tfhe::FheInt32,
    i32,
    tfhe::FheInt32ConformanceParams
);
typed_evaluator!(
    eval_i64,
    tfhe::FheInt64,
    i64,
    tfhe::FheInt64ConformanceParams
);

/// Evaluates a job and returns the serialized encrypted result: a ciphertext of
/// the input type, or an `FheBool` for comparisons. CPU-heavy: call from a
/// blocking thread.
pub fn evaluate(key: &UserServerKey, job: &Job) -> Result<Vec<u8>, EvalError> {
    match job.integer_type {
        IntegerType::U8 => eval_u8(key, job),
        IntegerType::U16 => eval_u16(key, job),
        IntegerType::U32 => eval_u32(key, job),
        IntegerType::U64 => eval_u64(key, job),
        IntegerType::I8 => eval_i8(key, job),
        IntegerType::I16 => eval_i16(key, job),
        IntegerType::I32 => eval_i32(key, job),
        IntegerType::I64 => eval_i64(key, job),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::test_support::{client_key, public_key, user_server_key};
    use crate::crypto::params::proof_metadata;
    use crate::crypto::proofs::{test_support::crs, Crs};
    use heaas_core::PlainValue;
    use heaas_sdk::fhe;
    use tfhe::ClientKey;
    use IntegerType::*;

    // The tests play the client, with the SDK's encryption.
    fn encrypt(ck: &ClientKey, ty: IntegerType, value: i128) -> Vec<u8> {
        fhe::encrypt_as(ck, ty, value).unwrap()
    }

    fn decrypt(ck: &ClientKey, ty: heaas_core::ValueType, bytes: &[u8]) -> PlainValue {
        fhe::decrypt_as(ck, ty, bytes).unwrap()
    }

    fn prove(key_id: &str, ty: IntegerType, values: &[i128]) -> Vec<u8> {
        fhe::prove(public_key(), &crs().crs, key_id, ty, values).unwrap()
    }

    /// Encrypts `operands` (the last as a scalar if `scalar`), evaluates and
    /// decrypts, checking the result against the plaintext semantics.
    fn check(op: Operation, ty: IntegerType, operands: &[i128], scalar: bool) {
        let ck = client_key();
        let (encrypted, scalar_value) = if scalar {
            (&operands[..operands.len() - 1], operands.last().copied())
        } else {
            (operands, None)
        };
        let inputs: Vec<_> = encrypted.iter().map(|&v| encrypt(ck, ty, v)).collect();
        let job = Job {
            operation: op,
            integer_type: ty,
            scalar: scalar_value,
            inputs: Inputs::Ciphertexts(&inputs),
        };
        let out = evaluate(&user_server_key(), &job).unwrap();
        assert_eq!(
            decrypt(ck, op.result_type(ty), &out),
            op.apply_plain(ty, operands),
            "{op}{} on {ty} {operands:?}",
            if scalar { " (scalar)" } else { "" }
        );
    }

    #[test]
    fn every_operation_matches_plaintext_semantics_on_16_bits() {
        // Wrap-around (overflow and underflow), equal operands, extremes.
        let cases = [(40_000, 30_000), (7, 9), (65_535, 1), (0, 0)];
        for op in Operation::ALL
            .into_iter()
            .filter(|&op| op != Operation::Sum)
        {
            for (a, b) in cases {
                check(op, U16, &[a, b], false);
            }
        }
    }

    #[test]
    fn results_a_scalar_makes_trivial_are_still_encrypted() {
        // x * 0, x * -128 (a shift), and x < 0 / x >= 0 on unsigned types are
        // known without the input; their results must still be ciphertexts.
        let ck = client_key();
        for (op, ty, a, scalar) in [
            (Operation::Multiply, U8, 200, 0),
            (Operation::Multiply, I8, -128, -128),
            (Operation::Lt, U8, 200, 0),
            (Operation::Ge, U8, 200, 0),
        ] {
            let inputs = [encrypt(ck, ty, a)];
            let job = Job {
                operation: op,
                integer_type: ty,
                scalar: Some(scalar),
                inputs: Inputs::Ciphertexts(&inputs),
            };
            let out = evaluate(&user_server_key(), &job).unwrap();
            assert_eq!(
                decrypt(ck, op.result_type(ty), &out),
                op.apply_plain(ty, &[a, scalar]),
                "{op} {ty}"
            );
            // Accepted again as an input (the conformance check of `decrypt`
            // already refused trivial ciphertexts).
            if op == Operation::Multiply {
                check_feeds_back(ty, out);
            }
        }
    }

    fn check_feeds_back(ty: IntegerType, ciphertext: Vec<u8>) {
        let inputs = [ciphertext, encrypt(client_key(), ty, 1)];
        evaluate(&user_server_key(), &ciphertext_job(ty, &inputs)).unwrap();
    }

    #[test]
    fn every_operation_takes_a_scalar_on_signed_8_bits() {
        for op in Operation::ALL
            .into_iter()
            .filter(|&op| op != Operation::Sum)
        {
            for (a, b) in [(-100, 100), (127, -1), (-128, -128)] {
                check(op, I8, &[a, b], true);
            }
        }
    }

    #[test]
    fn every_type_computes_and_compares() {
        for ty in IntegerType::ALL {
            let (min, max) = (ty.min_value(), ty.max_value());
            check(Operation::Add, ty, &[max, 1], false);
            check(Operation::Lt, ty, &[min, max], false);
            check(Operation::Subtract, ty, &[min, 1], true);
        }
    }

    #[test]
    fn sums_many_inputs_with_wrap_around() {
        check(Operation::Sum, U8, &[200, 100, 30, 1], false);
        check(Operation::Sum, I16, &[-30_000, -30_000, 5, 7, 11], false);
    }

    #[test]
    fn results_can_be_fed_back_as_inputs() {
        let ck = client_key();
        let key = user_server_key();
        let first = [encrypt(ck, U16, 1_000), encrypt(ck, U16, 2_000)];
        let sum = evaluate(
            &key,
            &Job {
                operation: Operation::Add,
                integer_type: U16,
                scalar: None,
                inputs: Inputs::Ciphertexts(&first),
            },
        )
        .unwrap();
        let second = [sum, encrypt(ck, U16, 3)];
        let product = evaluate(
            &key,
            &Job {
                operation: Operation::Multiply,
                integer_type: U16,
                scalar: None,
                inputs: Inputs::Ciphertexts(&second),
            },
        )
        .unwrap();
        assert_eq!(decrypt(ck, U16.into(), &product), PlainValue::Int(9_000));
    }

    fn ciphertext_job<'a>(ty: IntegerType, inputs: &'a [Vec<u8>]) -> Job<'a> {
        Job {
            operation: Operation::Add,
            integer_type: ty,
            scalar: None,
            inputs: Inputs::Ciphertexts(inputs),
        }
    }

    #[test]
    fn rejects_malformed_and_foreign_ciphertexts_without_panicking() {
        let ck = client_key();
        let key = user_server_key();
        let good = encrypt(ck, U16, 5);

        let truncated = good[..good.len() / 2].to_vec();
        for bad in [b"not a ciphertext".to_vec(), truncated, Vec::new()] {
            let inputs = [bad, good.clone()];
            let err = evaluate(&key, &ciphertext_job(U16, &inputs)).unwrap_err();
            assert!(matches!(err, EvalError::InvalidInput(_)), "{err}");
        }

        // A well-formed ciphertext of another type.
        let inputs = [good.clone(), encrypt(ck, U8, 1)];
        assert!(matches!(
            evaluate(&key, &ciphertext_job(U16, &inputs)),
            Err(EvalError::InvalidInput(_))
        ));
        // The wrong number of inputs.
        let inputs = [good.clone(), good.clone(), good];
        assert!(matches!(
            evaluate(&key, &ciphertext_job(U16, &inputs)),
            Err(EvalError::InvalidInput(_))
        ));
    }

    #[test]
    fn proven_inputs_verify_and_compute() {
        let (ck, crs) = (client_key(), crs());
        let key = user_server_key();
        let metadata = proof_metadata("key-1");
        let list = prove("key-1", I32, &[-7, 1_000_000]);
        assert_eq!(proven_input_count(&list, &crs.crs, I32).unwrap(), 2);
        assert!(proven_input_count(&list, &crs.crs, U32).is_err());

        fn job<'a>(list: &'a [u8], crs: &'a Crs, metadata: &'a [u8], op: Operation) -> Job<'a> {
            Job {
                operation: op,
                integer_type: I32,
                scalar: None,
                inputs: Inputs::Proven {
                    list,
                    proof: ProofContext {
                        crs: &crs.crs,
                        public_key: public_key(),
                        metadata,
                    },
                },
            }
        }
        let out = evaluate(&key, &job(&list, &crs, &metadata, Operation::Multiply)).unwrap();
        assert_eq!(decrypt(ck, I32.into(), &out), PlainValue::Int(-7_000_000));

        // A proof made for another key does not verify.
        let other = proof_metadata("key-2");
        assert!(matches!(
            evaluate(&key, &job(&list, &crs, &other, Operation::Add)),
            Err(EvalError::InvalidInput(_))
        ));
    }

    #[test]
    fn proven_lists_are_checked_for_shape() {
        let crs = crs();
        let metadata = proof_metadata("k");
        let three = prove("k", U8, &[1, 2, 3]);
        assert_eq!(proven_input_count(&three, &crs.crs, U8).unwrap(), 3);
        // Three inputs are too many for a binary operation.
        let job = Job {
            operation: Operation::Add,
            integer_type: U8,
            scalar: None,
            inputs: Inputs::Proven {
                list: &three,
                proof: ProofContext {
                    crs: &crs.crs,
                    public_key: public_key(),
                    metadata: &metadata,
                },
            },
        };
        assert!(matches!(
            evaluate(&user_server_key(), &job),
            Err(EvalError::InvalidInput(_))
        ));
        for bad in [&b"garbage"[..], &three[..three.len() / 2], &[]] {
            assert!(proven_input_count(bad, &crs.crs, U8).is_err());
        }
    }
}
