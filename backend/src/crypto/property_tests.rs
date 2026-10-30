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
use heaas_core::program::{Arg, Kind, Program, ProgramOp, Step};
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
        proptest::sample::select(Operation::BASIC.to_vec()),
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
        program: None,
    };
    let out = evaluate(&user_server_key(), &job).map_err(|e| TestCaseError::fail(e.to_string()))?;
    let decrypted = fhe::decrypt_as(ck, op.result_type(ty), &out)
        .map_err(|e| TestCaseError::fail(e.to_string()))?;
    prop_assert_eq!(decrypted, op.apply_plain(ty, operands));
    Ok(())
}

/// A random well-typed program on `inputs` inputs of type `ty`, driven by
/// `choices` (four per step).
fn random_program(ty: IntegerType, inputs: usize, choices: &[u32]) -> Program {
    let mut steps: Vec<Step> = Vec::new();
    let mut kinds: Vec<Kind> = Vec::new();
    for c in choices.as_chunks::<4>().0 {
        let ints: Vec<Arg> = (0..inputs)
            .map(Arg::Input)
            .chain(
                (0..steps.len())
                    .filter(|&s| kinds[s] == Kind::Int)
                    .map(Arg::Step),
            )
            .collect();
        let bools: Vec<Arg> = (0..steps.len())
            .filter(|&s| kinds[s] == Kind::Bool)
            .map(Arg::Step)
            .collect();
        let int = |n: u32| ints[n as usize % ints.len()].clone();
        let constant = |n: u32| ty.wrap(n as i128 - (1 << 31)).to_string();
        let (op, args, kind) = match c[0] % 9 {
            0..=2 => {
                const ARITHMETIC: [ProgramOp; 10] = [
                    ProgramOp::Add,
                    ProgramOp::Subtract,
                    ProgramOp::Multiply,
                    ProgramOp::Divide,
                    ProgramOp::Remainder,
                    ProgramOp::Min,
                    ProgramOp::Max,
                    ProgramOp::And,
                    ProgramOp::Or,
                    ProgramOp::Xor,
                ];
                let op = ARITHMETIC[c[1] as usize % ARITHMETIC.len()];
                let divides = matches!(op, ProgramOp::Divide | ProgramOp::Remainder);
                let b = if c[2] % 2 == 0 {
                    int(c[3])
                } else {
                    let k = constant(c[3]);
                    Arg::Const(if divides && k == "0" { "1".into() } else { k })
                };
                (op, vec![int(c[2]), b], Kind::Int)
            }
            3 => {
                const COMPARISONS: [ProgramOp; 6] = [
                    ProgramOp::Eq,
                    ProgramOp::Ne,
                    ProgramOp::Lt,
                    ProgramOp::Le,
                    ProgramOp::Gt,
                    ProgramOp::Ge,
                ];
                let b = if c[2] % 2 == 0 {
                    int(c[3])
                } else {
                    Arg::Const(constant(c[3]))
                };
                (
                    COMPARISONS[c[1] as usize % 6],
                    vec![int(c[2]), b],
                    Kind::Bool,
                )
            }
            4 => {
                const SHIFTS: [ProgramOp; 4] = [
                    ProgramOp::Shl,
                    ProgramOp::Shr,
                    ProgramOp::Rotl,
                    ProgramOp::Rotr,
                ];
                let n = (c[3] % ty.bits()).to_string();
                (
                    SHIFTS[c[1] as usize % 4],
                    vec![int(c[2]), Arg::Const(n)],
                    Kind::Int,
                )
            }
            5 => {
                let op = match c[1] % 3 {
                    0 => ProgramOp::Not,
                    1 if ty.is_signed() => ProgramOp::Abs,
                    _ => ProgramOp::Neg,
                };
                (op, vec![int(c[2])], Kind::Int)
            }
            6 | 7 if !bools.is_empty() => {
                let condition = bools[c[1] as usize % bools.len()].clone();
                (
                    ProgramOp::Select,
                    vec![condition, int(c[2]), int(c[3])],
                    Kind::Int,
                )
            }
            _ if !bools.is_empty() => {
                const LOGIC: [ProgramOp; 4] = [
                    ProgramOp::And,
                    ProgramOp::Or,
                    ProgramOp::Xor,
                    ProgramOp::Not,
                ];
                let op = LOGIC[c[1] as usize % 4];
                let p = bools[c[2] as usize % bools.len()].clone();
                let args = if op == ProgramOp::Not {
                    vec![p]
                } else {
                    vec![p, bools[c[3] as usize % bools.len()].clone()]
                };
                (op, args, Kind::Bool)
            }
            _ => (ProgramOp::Add, vec![int(c[2]), int(c[3])], Kind::Int),
        };
        steps.push(Step { op, args });
        kinds.push(kind);
    }
    Program { steps }
}

/// Runs a random program homomorphically and against the oracle.
fn check_program(ty: IntegerType, values: &[i128], choices: &[u32]) -> Result<(), TestCaseError> {
    let program = random_program(ty, values.len(), choices);
    let checked = program
        .check(ty, values.len())
        .map_err(|e| TestCaseError::fail(format!("generated an invalid program: {e}")))?;
    let ck = client_key();
    let inputs: Vec<_> = values
        .iter()
        .map(|&v| fhe::encrypt_as(ck, ty, v).unwrap())
        .collect();
    let job = Job {
        operation: Operation::Program,
        integer_type: ty,
        scalar: None,
        inputs: Inputs::Ciphertexts(&inputs),
        program: Some(&checked),
    };
    let out = evaluate(&user_server_key(), &job).map_err(|e| TestCaseError::fail(e.to_string()))?;
    let decrypted = fhe::decrypt_as(ck, checked.result_type(), &out)
        .map_err(|e| TestCaseError::fail(e.to_string()))?;
    prop_assert_eq!(decrypted, checked.eval_plain(values), "{:?}", program);
    Ok(())
}

fn program_cases(
    types: Vec<IntegerType>,
    max_steps: usize,
) -> impl Strategy<Value = (IntegerType, Vec<i128>, Vec<u32>)> {
    (proptest::sample::select(types), 1..=3usize, 1..=max_steps).prop_flat_map(
        |(ty, inputs, steps)| {
            (
                Just(ty),
                proptest::collection::vec(ty.min_value()..=ty.max_value(), inputs),
                proptest::collection::vec(any::<u32>(), steps * 4),
            )
        },
    )
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
        let job = Job { operation: Operation::Add, integer_type: ty, scalar: None, inputs: Inputs::Ciphertexts(&inputs), program: None };
        prop_assert!(matches!(evaluate(&user_server_key(), &job), Err(EvalError::InvalidInput(_))));
    }

    #[test]
    fn corrupted_ciphertexts_never_crash_the_evaluator(position in any::<usize>(), mask in any::<u8>()) {
        let good = fhe::encrypt_as(client_key(), IntegerType::U8, 7).unwrap();
        let inputs = [flip(&good, position, mask), good];
        let job = Job { operation: Operation::Add, integer_type: IntegerType::U8, scalar: None, inputs: Inputs::Ciphertexts(&inputs), program: None };
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
                program: None,
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
    #![proptest_config(cases(6))]

    #[test]
    fn random_programs_match_the_oracle(
        (ty, values, choices) in program_cases(vec![IntegerType::U8, IntegerType::I8], 4)
    ) {
        check_program(ty, &values, &choices)?;
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
    #[ignore = "heavy: programs on every type; run by the scheduled workflow"]
    fn heavy_random_programs_match_the_oracle_on_every_type(
        (ty, values, choices) in program_cases(IntegerType::ALL.to_vec(), 8)
    ) {
        check_program(ty, &values, &choices)?;
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
            program: None,
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
