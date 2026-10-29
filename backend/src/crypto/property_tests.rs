//! Property tests: homomorphic results against the plaintext oracle on random
//! operations, types and values, and the deserialization paths against random
//! and corrupted bytes.
//!
//! TFHE operations are slow, so the default case counts are small enough for
//! every CI run. The `#[ignore]`d `heavy_*` tests cover every type (64-bit
//! multiplications included) with more cases; the scheduled `heavy` workflow
//! runs them (`cargo test --release -p he-backend -- --ignored`).

use crate::crypto::eval::{evaluate, proven_input_count, EvalError, Inputs, Job, ProofContext};
use crate::crypto::keys::test_support::{
    client_key, compressed_server_key_bytes, public_key, public_key_bytes, user_server_key,
};
use crate::crypto::keys::{validate_compressed_key, validate_public_key};
use crate::crypto::params::proof_metadata;
use crate::crypto::proofs::test_support::crs;
use heaas_core::{IntegerType, Operation};
use heaas_sdk::fhe;
use proptest::prelude::*;
use proptest::test_runner::Config;

/// `HEAAS_PROPTEST_CASES` overrides the case count (the heavy workflow raises it).
fn cases(default: u32) -> Config {
    let cases = std::env::var("HEAAS_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default);
    Config {
        cases,
        // Shrinking re-runs TFHE operations many times; the failing input is
        // printed either way.
        max_shrink_iters: 16,
        ..Config::default()
    }
}

/// A random job: the operation, its type, the plaintext operands (the scalar
/// last, if any) and whether the last operand is sent as a scalar.
fn jobs(
    types: Vec<IntegerType>,
) -> impl Strategy<Value = (Operation, IntegerType, Vec<i128>, bool)> {
    (
        proptest::sample::select(Operation::ALL.to_vec()),
        proptest::sample::select(types),
        any::<bool>(),
    )
        .prop_flat_map(|(op, ty, scalar)| {
            let scalar = scalar && op != Operation::Sum;
            let count = if op == Operation::Sum { 2..=4 } else { 2..=2 };
            let values = proptest::collection::vec(ty.min_value()..=ty.max_value(), count);
            (Just(op), Just(ty), values, Just(scalar))
        })
}

/// Encrypts, evaluates and decrypts one job; the result must match the oracle.
fn check_job(
    op: Operation,
    ty: IntegerType,
    operands: &[i128],
    scalar: bool,
) -> Result<(), TestCaseError> {
    let ck = client_key();
    let (encrypted, scalar_value) = if scalar {
        (&operands[..operands.len() - 1], operands.last().copied())
    } else {
        (operands, None)
    };
    let inputs: Vec<_> = encrypted
        .iter()
        .map(|&v| fhe::encrypt_as(ck, ty, v).unwrap())
        .collect();
    let job = Job {
        operation: op,
        integer_type: ty,
        scalar: scalar_value,
        inputs: Inputs::Ciphertexts(&inputs),
    };
    let out = evaluate(&user_server_key(), &job).map_err(|e| TestCaseError::fail(e.to_string()))?;
    let decrypted = fhe::decrypt_as(ck, op.result_type(ty), &out)
        .map_err(|e| TestCaseError::fail(e.to_string()))?;
    prop_assert_eq!(decrypted, op.apply_plain(ty, operands));
    Ok(())
}

/// Corrupts one byte of `bytes` (flipping the bits in `mask`, at least one).
fn flip(bytes: &[u8], position: usize, mask: u8) -> Vec<u8> {
    let mut corrupted = bytes.to_vec();
    let i = position % corrupted.len();
    corrupted[i] ^= mask.max(1);
    corrupted
}

/// Untrusted bytes are refused as the caller's fault or accepted, never a
/// panic or an internal error.
fn caller_error_or_ok(result: Result<Vec<u8>, EvalError>) -> Result<(), TestCaseError> {
    match result {
        Ok(_) | Err(EvalError::InvalidInput(_)) => Ok(()),
        Err(EvalError::Internal(e)) => Err(TestCaseError::fail(format!("internal error: {e}"))),
    }
}

const SMALL_TYPES: [IntegerType; 4] = [
    IntegerType::U8,
    IntegerType::I8,
    IntegerType::U16,
    IntegerType::I16,
];

proptest! {
    #![proptest_config(cases(8))]

    #[test]
    fn homomorphic_results_match_the_oracle((op, ty, operands, scalar) in jobs(SMALL_TYPES.to_vec())) {
        check_job(op, ty, &operands, scalar)?;
    }

    #[test]
    fn random_bytes_are_refused_as_ciphertexts(
        ty in proptest::sample::select(IntegerType::ALL.to_vec()),
        garbage in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let good = fhe::encrypt_as(client_key(), ty, 1).unwrap();
        let inputs = [garbage, good];
        let job = Job { operation: Operation::Add, integer_type: ty, scalar: None, inputs: Inputs::Ciphertexts(&inputs) };
        prop_assert!(matches!(evaluate(&user_server_key(), &job), Err(EvalError::InvalidInput(_))));
    }

    #[test]
    fn corrupted_ciphertexts_never_crash_the_evaluator(position in any::<usize>(), mask in any::<u8>()) {
        let good = fhe::encrypt_as(client_key(), IntegerType::U8, 7).unwrap();
        let inputs = [flip(&good, position, mask), good];
        let job = Job { operation: Operation::Add, integer_type: IntegerType::U8, scalar: None, inputs: Inputs::Ciphertexts(&inputs) };
        caller_error_or_ok(evaluate(&user_server_key(), &job))?;
    }

    #[test]
    fn corrupted_proven_lists_are_refused(position in any::<usize>(), mask in any::<u8>()) {
        let crs = crs();
        let list = fhe::prove(public_key(), &crs.crs, "k", IntegerType::U8, &[3, 4]).unwrap();
        let corrupted = flip(&list, position, mask);
        if proven_input_count(&corrupted, &crs.crs, IntegerType::U8).is_ok() {
            let metadata = proof_metadata("k");
            let job = Job {
                operation: Operation::Add,
                integer_type: IntegerType::U8,
                scalar: None,
                inputs: Inputs::Proven {
                    list: &corrupted,
                    proof: ProofContext { crs: &crs.crs, public_key: public_key(), metadata: &metadata },
                },
            };
            // A corrupted proof or ciphertext must not verify. A byte that does
            // not matter (e.g. in a tag) may be accepted, but then the inputs
            // are unchanged: the result is still 3 + 4.
            match evaluate(&user_server_key(), &job) {
                Err(EvalError::InvalidInput(_)) => {}
                Err(EvalError::Internal(e)) => return Err(TestCaseError::fail(e)),
                Ok(out) => prop_assert_eq!(
                    fhe::decrypt_as(client_key(), heaas_core::ValueType::U8, &out).unwrap(),
                    heaas_core::PlainValue::Int(7)
                ),
            }
        }
    }

    #[test]
    fn corrupted_public_keys_never_crash_validation(position in any::<usize>(), mask in any::<u8>()) {
        let _ = validate_public_key(&flip(public_key_bytes(), position, mask));
    }
}

proptest! {
    #![proptest_config(cases(2))]

    /// Server keys are ~60 MB: a few corruptions, in the header and the body.
    #[test]
    fn corrupted_server_keys_never_crash_validation(position in any::<usize>(), mask in any::<u8>()) {
        let bytes = compressed_server_key_bytes();
        let header = flip(bytes, position % 256, mask);
        let _ = validate_compressed_key(&header, 1 << 30);
        let _ = validate_compressed_key(&flip(bytes, position, mask), 1 << 30);
    }
}

proptest! {
    #![proptest_config(cases(64))]

    #[test]
    #[ignore = "heavy: every type, 64-bit multiplications; run by the scheduled workflow"]
    fn heavy_homomorphic_results_match_the_oracle_on_every_type(
        (op, ty, operands, scalar) in jobs(IntegerType::ALL.to_vec())
    ) {
        check_job(op, ty, &operands, scalar)?;
    }

    #[test]
    #[ignore = "heavy: proofs on every type; run by the scheduled workflow"]
    fn heavy_proven_inputs_match_the_oracle(
        (op, ty, operands, _) in jobs(IntegerType::ALL.to_vec())
    ) {
        let crs = crs();
        let list = fhe::prove(public_key(), &crs.crs, "k", ty, &operands).unwrap();
        let metadata = proof_metadata("k");
        let job = Job {
            operation: op,
            integer_type: ty,
            scalar: None,
            inputs: Inputs::Proven {
                list: &list,
                proof: ProofContext { crs: &crs.crs, public_key: public_key(), metadata: &metadata },
            },
        };
        let out = evaluate(&user_server_key(), &job).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let decrypted = fhe::decrypt_as(client_key(), op.result_type(ty), &out).unwrap();
        prop_assert_eq!(decrypted, op.apply_plain(ty, &operands));
    }
}
