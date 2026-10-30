//! Homomorphic evaluation under a user's own server key.
//!
//! The server never holds a client (secret) key: it deserializes the caller's
//! ciphertexts, checks they conform to the caller's key (and, for proven inputs,
//! that their zero-knowledge proof verifies), computes, and returns an encrypted
//! result only the caller can decrypt. A job is one operation or a
//! [program](heaas_core::program) of several, whose intermediate values stay
//! encrypted and which may return several results. Results are serialized one
//! ciphertext each or, on request, together as one TFHE-rs
//! `CompressedCiphertextList` (about 2 KB instead of 130–530 KB per value).

use crate::crypto::keys::UserServerKey;
use crate::crypto::params::{
    proven_list_conformance, MAX_CIPHERTEXT_BYTES, MAX_COMPRESSED_RESULT_BYTES,
    MAX_PROVEN_LIST_BYTES,
};
use std::fmt;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize_conformant, safe_serialize};
use tfhe::zk::CompactPkeCrs;
use tfhe::{
    set_server_key, CompactPublicKey, CompressedCiphertextListBuilder, FheBool,
    FheBoolConformanceParams, FheTypes, MatchValues, ProvenCompactCiphertextList,
};

use heaas_core::program::{CheckedProgram, Operand, ProgramOp, Ref};
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
    /// For [`Operation::Program`]: the checked program.
    pub program: Option<&'a CheckedProgram>,
    /// Return the results as one compressed list (the key must have compression
    /// keys: [`UserServerKey::supports_compression`]).
    pub compress: bool,
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

/// A computed value: an integer of the job's type or a boolean.
#[derive(Clone)]
enum Output<T> {
    Int(T),
    Bool(FheBool),
}

/// An argument while a program runs.
enum Val<'v, T> {
    Int(&'v T),
    Bool(&'v FheBool),
    Const(i128),
}

/// `abs` exists for signed types only; programs are type-checked so it is
/// never reached for unsigned ones.
trait SignedAbs: Sized {
    fn signed_abs(&self) -> Option<Self>;
}

macro_rules! signed_abs {
    ($($signed:ty),*; $($unsigned:ty),*) => {
        $(impl SignedAbs for $signed {
            fn signed_abs(&self) -> Option<Self> {
                Some(self.abs())
            }
        })*
        $(impl SignedAbs for $unsigned {
            fn signed_abs(&self) -> Option<Self> {
                None
            }
        })*
    };
}

signed_abs!(tfhe::FheInt8, tfhe::FheInt16, tfhe::FheInt32, tfhe::FheInt64;
            tfhe::FheUint8, tfhe::FheUint16, tfhe::FheUint32, tfhe::FheUint64);

/// A lookup table on a ciphertext, with TFHE-rs's `match_value_or` (unsigned
/// types only): a signed value is matched on its two's-complement bits, through
/// the unsigned type of the same width.
trait Lookup: Sized {
    fn lookup(&self, table: &[(i128, i128)], default: i128) -> Result<Self, EvalError>;
}

/// The two's-complement bits of `value` in a `bits`-wide integer.
fn bit_pattern(value: i128, bits: u32) -> u64 {
    (value as u64) & (u64::MAX >> (64 - bits))
}

fn match_values(table: &[(i128, i128)], bits: u32) -> Result<MatchValues<u64>, EvalError> {
    MatchValues::new(
        table
            .iter()
            .map(|&(k, v)| (bit_pattern(k, bits), bit_pattern(v, bits)))
            .collect(),
    )
    .map_err(|_| mismatch())
}

macro_rules! lookup {
    ($($unsigned:ty),*; $($signed:ty => $same_width:ty),*) => {
        $(impl Lookup for $unsigned {
            fn lookup(&self, table: &[(i128, i128)], default: i128) -> Result<Self, EvalError> {
                let bits = <$unsigned>::num_bits() as u32;
                self.match_value_or(&match_values(table, bits)?, bit_pattern(default, bits))
                    .map_err(|e| EvalError::Internal(format!("lookup: {e}")))
            }
        })*
        $(impl Lookup for $signed {
            fn lookup(&self, table: &[(i128, i128)], default: i128) -> Result<Self, EvalError> {
                let bits = <$same_width>::num_bits() as u32;
                let bits_of_self = <$same_width>::cast_from(self.clone());
                let found: $same_width = bits_of_self
                    .match_value_or(&match_values(table, bits)?, bit_pattern(default, bits))
                    .map_err(|e| EvalError::Internal(format!("lookup: {e}")))?;
                Ok(<$signed>::cast_from(found))
            }
        })*
    };
}

lookup!(tfhe::FheUint8, tfhe::FheUint16, tfhe::FheUint32, tfhe::FheUint64;
        tfhe::FheInt8 => tfhe::FheUint8, tfhe::FheInt16 => tfhe::FheUint16,
        tfhe::FheInt32 => tfhe::FheUint32, tfhe::FheInt64 => tfhe::FheUint64);

fn mismatch() -> EvalError {
    EvalError::Internal("the program does not match its checked types".into())
}

fn as_int<T>(v: Val<'_, T>) -> Result<&T, EvalError> {
    match v {
        Val::Int(x) => Ok(x),
        _ => Err(mismatch()),
    }
}

fn as_bool<T>(v: Val<'_, T>) -> Result<&FheBool, EvalError> {
    match v {
        Val::Bool(b) => Ok(b),
        _ => Err(mismatch()),
    }
}

fn as_const<C: TryFrom<i128>, T>(v: Val<'_, T>) -> Result<C, EvalError> {
    match v {
        Val::Const(c) => C::try_from(c).map_err(|_| mismatch()),
        _ => Err(mismatch()),
    }
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
            Operation::Sum | Operation::Program => unreachable!("not a binary operation"),
        }
    };
}

/// A program step on two integers, `$b` a ciphertext reference or a scalar.
macro_rules! apply_step {
    ($op:expr, $a:expr, $b:expr) => {
        match $op {
            ProgramOp::Add => Output::Int($a + $b),
            ProgramOp::Subtract => Output::Int($a - $b),
            ProgramOp::Multiply => Output::Int($a * $b),
            ProgramOp::Divide => Output::Int($a / $b),
            ProgramOp::Remainder => Output::Int($a % $b),
            ProgramOp::Min => Output::Int($a.min($b)),
            ProgramOp::Max => Output::Int($a.max($b)),
            ProgramOp::And => Output::Int($a & $b),
            ProgramOp::Or => Output::Int($a | $b),
            ProgramOp::Xor => Output::Int($a ^ $b),
            ProgramOp::Eq => Output::Bool($a.eq($b)),
            ProgramOp::Ne => Output::Bool($a.ne($b)),
            ProgramOp::Lt => Output::Bool($a.lt($b)),
            ProgramOp::Le => Output::Bool($a.le($b)),
            ProgramOp::Gt => Output::Bool($a.gt($b)),
            ProgramOp::Ge => Output::Bool($a.ge($b)),
            _ => return Err(mismatch()),
        }
    };
}

/// Runs a checked program on `$inputs` (a `Vec<$fhe>`); the outputs' values.
macro_rules! run_program {
    ($fhe:ty, $clear:ty, $program:expr, $inputs:expr) => {{
        let inputs: &[$fhe] = $inputs;
        let mut results: Vec<Output<$fhe>> = Vec::with_capacity($program.steps.len());
        for step in &$program.steps {
            let arg = |k: usize| -> Result<Val<'_, $fhe>, EvalError> {
                Ok(match step.args.get(k).ok_or_else(mismatch)? {
                    Operand::Value(Ref::Input(i)) => Val::Int(inputs.get(*i).ok_or_else(mismatch)?),
                    Operand::Value(Ref::Step(s)) => match results.get(*s).ok_or_else(mismatch)? {
                        Output::Int(x) => Val::Int(x),
                        Output::Bool(b) => Val::Bool(b),
                    },
                    Operand::Const(c) => Val::Const(*c),
                })
            };
            let (int, boolean) = (as_int::<$fhe>, as_bool::<$fhe>);
            let constant = as_const::<$clear, $fhe>;
            let out: Output<$fhe> = match (step.op, arg(0)?) {
                (ProgramOp::Not, Val::Int(x)) => Output::Int(!x),
                (ProgramOp::Not, Val::Bool(b)) => Output::Bool(!b),
                (ProgramOp::Neg, Val::Int(x)) => Output::Int(-x),
                (ProgramOp::Abs, Val::Int(x)) => Output::Int(x.signed_abs().ok_or_else(mismatch)?),
                (ProgramOp::Lookup, Val::Int(x)) => {
                    let default = i128::from(constant(arg(1)?)?);
                    Output::Int(x.lookup(&step.table, default)?)
                }
                (ProgramOp::Select, Val::Bool(c)) => {
                    Output::Int(c.if_then_else(int(arg(1)?)?, int(arg(2)?)?))
                }
                (
                    op @ (ProgramOp::Shl | ProgramOp::Shr | ProgramOp::Rotl | ProgramOp::Rotr),
                    Val::Int(x),
                ) => {
                    let n =
                        u32::try_from(i128::from(constant(arg(1)?)?)).map_err(|_| mismatch())?;
                    Output::Int(match op {
                        ProgramOp::Shl => x << n,
                        ProgramOp::Shr => x >> n,
                        ProgramOp::Rotl => x.rotate_left(n),
                        _ => x.rotate_right(n),
                    })
                }
                (op @ (ProgramOp::And | ProgramOp::Or | ProgramOp::Xor), Val::Bool(p)) => {
                    let q = boolean(arg(1)?)?;
                    Output::Bool(match op {
                        ProgramOp::And => p & q,
                        ProgramOp::Or => p | q,
                        _ => p ^ q,
                    })
                }
                (op, Val::Int(x)) => match arg(1)? {
                    Val::Int(y) => apply_step!(op, x, y),
                    c @ Val::Const(_) => {
                        let c = constant(c)?;
                        apply_step!(op, x, c)
                    }
                    Val::Bool(_) => return Err(mismatch()),
                },
                _ => return Err(mismatch()),
            };
            results.push(out);
        }
        $program
            .outputs
            .iter()
            .map(|&o| results.get(o).cloned().ok_or_else(mismatch))
            .collect::<Result<Vec<_>, _>>()?
    }};
}

/// The whole evaluation for one TFHE-rs type.
macro_rules! evaluate_as {
    ($fhe:ty, $clear:ty, $conformance:ty, $key:expr, $job:expr) => {{
        let (key, job): (&UserServerKey, &Job) = ($key, $job);
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
                    .map_err(|_| invalid("The proof of the inputs does not verify for this key"))?;
                (0..list.len())
                    .map(|i| match expander.get::<$fhe>(i) {
                        Ok(Some(value)) => Ok(value),
                        _ => Err(invalid(format!(
                            "Proven input {} is not a {tfhe_name}",
                            i + 1
                        ))),
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
        let outputs: Vec<Output<$fhe>> = match (job.operation, job.scalar) {
            (Operation::Program, _) => {
                let program = job
                    .program
                    .ok_or_else(|| EvalError::Internal("program missing".into()))?;
                if program.input_count != values.len() || program.integer_type != job.integer_type {
                    return Err(invalid(format!(
                        "The program reads {} inputs, but the job has {}",
                        program.input_count,
                        values.len()
                    )));
                }
                run_program!($fhe, $clear, program, &values)
            }
            (Operation::Sum, _) => vec![Output::Int(values.iter().sum::<$fhe>())],
            (op, Some(scalar)) => {
                let scalar = <$clear>::try_from(scalar).map_err(|_| {
                    invalid(format!(
                        "The scalar is outside the {} range",
                        job.integer_type
                    ))
                })?;
                vec![apply!(op, &values[0], scalar)]
            }
            (op, None) => vec![apply!(op, &values[0], &values[1])],
        };

        // Results must be ciphertexts clients (and later jobs) accept as
        // conformant. With a scalar, TFHE-rs leaves parts it can compute
        // without the inputs (e.g. `x * 0`, the low blocks of `x * 4`,
        // `x < 0` unsigned) as trivial, unencrypted blocks (so can a lookup
        // whose values are all equal); mixing in an encryption of zero (or
        // false) derived from an input fixes them.
        let input = &values[0];
        let not_conformant = || EvalError::Internal("result is not conformant".into());
        let serialize_failed = |e| EvalError::Internal(format!("serializing result: {e}"));
        let mut list = CompressedCiphertextListBuilder::new();
        let mut serialized = Vec::new();
        for output in outputs {
            let mut out = Vec::new();
            match output {
                Output::Int(mut result) => {
                    let conformance = <$conformance>::from(&key.server_key);
                    if !result.is_conformant(&conformance) {
                        let zero = input - input;
                        result = &result + &zero;
                    }
                    if !result.is_conformant(&conformance) {
                        return Err(not_conformant());
                    }
                    if job.compress {
                        list.push(result);
                        continue;
                    }
                    safe_serialize(&result, &mut out, MAX_CIPHERTEXT_BYTES)
                }
                Output::Bool(mut result) => {
                    let conformance = FheBoolConformanceParams::from(&key.server_key);
                    if !result.is_conformant(&conformance) {
                        let known = result.try_decrypt_trivial().map_err(|_| not_conformant())?;
                        let fresh_false = input.ne(input);
                        result = if known { !fresh_false } else { fresh_false };
                    }
                    if !result.is_conformant(&conformance) {
                        return Err(not_conformant());
                    }
                    if job.compress {
                        list.push(result);
                        continue;
                    }
                    safe_serialize(&result, &mut out, MAX_CIPHERTEXT_BYTES)
                }
            }
            .map_err(serialize_failed)?;
            serialized.push(out);
        }
        if job.compress {
            let list = list
                .build()
                .map_err(|e| EvalError::Internal(format!("compressing results: {e}")))?;
            let mut out = Vec::new();
            safe_serialize(&list, &mut out, MAX_COMPRESSED_RESULT_BYTES)
                .map_err(serialize_failed)?;
            serialized.push(out);
        }
        Ok(serialized)
    }};
}

/// Evaluates a job and returns its serialized encrypted results: one ciphertext
/// per output (of the input type, or an `FheBool` for comparisons), or a single
/// compressed list of them all if the job asks for it. CPU-heavy: call from a
/// blocking thread.
pub fn evaluate(key: &UserServerKey, job: &Job) -> Result<Vec<Vec<u8>>, EvalError> {
    if job.compress && !key.supports_compression {
        return Err(invalid(
            "This server key was made without compression keys and cannot compress results",
        ));
    }
    heaas_core::with_fhe_type!(job.integer_type, Fhe, Clear, Conformance => {
        evaluate_as!(Fhe, Clear, Conformance, key, job)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::test_support::{
        client_key, compressing_keys, public_key, user_server_key,
    };
    use crate::crypto::params::proof_metadata;
    use crate::crypto::proofs::{test_support::crs, Crs};
    use heaas_core::{PlainValue, ValueType};
    use heaas_sdk::fhe;
    use tfhe::ClientKey;
    use IntegerType::*;

    /// [`evaluate`] for jobs with one result.
    fn evaluate1(key: &UserServerKey, job: &Job) -> Result<Vec<u8>, EvalError> {
        evaluate(key, job).map(|mut results| {
            assert_eq!(results.len(), 1, "one result");
            results.remove(0)
        })
    }

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
            program: None,
            compress: false,
        };
        let out = evaluate1(&user_server_key(), &job).unwrap();
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
        for op in Operation::BASIC
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
                program: None,
                compress: false,
            };
            let out = evaluate1(&user_server_key(), &job).unwrap();
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
        evaluate1(&user_server_key(), &ciphertext_job(ty, &inputs)).unwrap();
    }

    #[test]
    fn every_operation_takes_a_scalar_on_signed_8_bits() {
        for op in Operation::BASIC
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

    /// Every program operation at least once, through the expression syntax.
    #[test]
    fn programs_cover_every_operation() {
        let ck = client_key();
        let cases: [(&str, IntegerType, &[i128]); 7] = [
            ("(a + b) * 3 - a / b + a % 7", I8, &[-100, 7]),
            ("min(a, b) ^ max(a, -3) | (a & 12)", I8, &[-5, 9]),
            ("abs(-a) + ~b", I8, &[-128, 3]),
            (
                "rotl(a, 3) + rotr(b, 1) - (a << 2) + (b >> 1)",
                I8,
                &[-75, 90],
            ),
            ("a / b + a % b", U8, &[200, 0]),
            ("lookup(a - b, [0: 1, 1: 2, -1: 3], -5)", I8, &[3, 4]),
            (
                "(a == b || a != 3) && !(a < b) ^ (a <= b) ? (a > b ? a : b) : (a >= 0 ? b : a)",
                I8,
                &[4, 4],
            ),
        ];
        for (expression, ty, values) in cases {
            let compiled = heaas_core::parse_expression(expression).unwrap();
            let checked = compiled.program.check(ty, compiled.input_count).unwrap();
            let inputs: Vec<_> = values.iter().map(|&v| encrypt(ck, ty, v)).collect();
            let job = Job {
                operation: Operation::Program,
                integer_type: ty,
                scalar: None,
                inputs: Inputs::Ciphertexts(&inputs),
                program: Some(&checked),
                compress: false,
            };
            let out = evaluate1(&user_server_key(), &job).unwrap();
            assert_eq!(
                decrypt(ck, checked.result_type(), &out),
                checked.eval_plain(values)[0],
                "{expression}"
            );
        }
        let used: std::collections::HashSet<_> = cases
            .iter()
            .flat_map(|(e, _, _)| heaas_core::parse_expression(e).unwrap().program.steps)
            .map(|s| s.op)
            .collect();
        for op in heaas_core::program::ProgramOp::ALL {
            assert!(used.contains(&op), "{op} is not covered");
        }
    }

    fn program_job<'a>(checked: &'a CheckedProgram, inputs: &'a [Vec<u8>]) -> Job<'a> {
        Job {
            operation: Operation::Program,
            integer_type: checked.integer_type,
            scalar: None,
            inputs: Inputs::Ciphertexts(inputs),
            program: Some(checked),
            compress: false,
        }
    }

    fn compile(expression: &str, ty: IntegerType) -> CheckedProgram {
        let compiled = heaas_core::parse_expression(expression).unwrap();
        compiled.program.check(ty, compiled.input_count).unwrap()
    }

    #[test]
    fn lookups_work_on_signed_and_unsigned_types() {
        let ck = client_key();
        let cases: [(&str, IntegerType, i128); 6] = [
            ("lookup(a, [1, 4, 9, 16], 255)", U8, 3),
            ("lookup(a, [1, 4, 9, 16], 255)", U8, 200),
            ("lookup(a, [-1: 100, -128: -1, 5: -128], 7)", I8, -128),
            ("lookup(a, [-1: 100, -128: -1, 5: -128], 7)", I8, 5),
            ("lookup(a, [-1: 100, -128: -1, 5: -128], 7)", I8, 0),
            ("lookup(a, [65535: 1, 0: 65535])", U16, 65_535),
        ];
        for (expression, ty, value) in cases {
            let checked = compile(expression, ty);
            let inputs = [encrypt(ck, ty, value)];
            let out = evaluate1(&user_server_key(), &program_job(&checked, &inputs)).unwrap();
            assert_eq!(
                decrypt(ck, ty.into(), &out),
                checked.eval_plain(&[value])[0],
                "{expression} on {value}"
            );
        }
        // Every value the same: the result is known without the input, and must
        // still come back encrypted (`decrypt` refuses trivial ciphertexts).
        let checked = compile("lookup(a, [3: 9], 9)", U8);
        let inputs = [encrypt(ck, U8, 1)];
        let out = evaluate1(&user_server_key(), &program_job(&checked, &inputs)).unwrap();
        assert_eq!(decrypt(ck, ValueType::U8, &out), PlainValue::Int(9));
    }

    #[test]
    fn programs_return_several_results() {
        let ck = client_key();
        let checked = compile("a + b, a < b, a, lookup(b, [0: 1], 2) * a", I16);
        let values = [-300, 7];
        let inputs: Vec<_> = values.iter().map(|&v| encrypt(ck, I16, v)).collect();
        let outputs = evaluate(&user_server_key(), &program_job(&checked, &inputs)).unwrap();
        let types = checked.result_types();
        assert_eq!(outputs.len(), 4);
        let decrypted: Vec<_> = outputs
            .iter()
            .zip(&types)
            .map(|(bytes, &ty)| decrypt(ck, ty, bytes))
            .collect();
        assert_eq!(decrypted, checked.eval_plain(&values));
    }

    #[test]
    fn results_come_back_compressed_for_keys_with_compression_keys() {
        let (ck, key) = compressing_keys();
        let checked = compile("a * b, a >= b, -a", I32);
        let values = [-70_000, 3];
        let inputs: Vec<_> = values.iter().map(|&v| encrypt(ck, I32, v)).collect();
        let mut job = program_job(&checked, &inputs);
        job.compress = true;
        let outputs = evaluate(&key, &job).unwrap();
        assert_eq!(outputs.len(), 1, "one list");
        assert!(outputs[0].len() < 20_000, "{} bytes", outputs[0].len());
        let values_back =
            fhe::decrypt_compressed(ck, &key.server_key, &outputs[0], &checked.result_types())
                .unwrap();
        assert_eq!(values_back, checked.eval_plain(&values));

        // A one-operation job, too.
        let pair = [encrypt(ck, U8, 200), encrypt(ck, U8, 100)];
        let mut add = ciphertext_job(U8, &pair);
        add.compress = true;
        let list = evaluate(&key, &add).unwrap();
        assert_eq!(
            fhe::decrypt_compressed(ck, &key.server_key, &list[0], &[ValueType::U8]).unwrap(),
            [PlainValue::Int(44)]
        );
        // The list holds what it holds.
        assert!(fhe::decrypt_compressed(ck, &key.server_key, &list[0], &[ValueType::U16]).is_err());
        assert!(fhe::decrypt_compressed(ck, &key.server_key, &list[0], &[]).is_err());

        // A key without compression keys refuses.
        let plain = [encrypt(client_key(), U8, 1), encrypt(client_key(), U8, 2)];
        let mut refused = ciphertext_job(U8, &plain);
        refused.compress = true;
        assert!(matches!(
            evaluate(&user_server_key(), &refused),
            Err(EvalError::InvalidInput(_))
        ));
    }

    #[test]
    fn a_program_must_match_its_inputs() {
        let ck = client_key();
        let compiled = heaas_core::parse_expression("a + b").unwrap();
        let checked = compiled.program.check(U8, 2).unwrap();
        let inputs = [encrypt(ck, U8, 1)];
        let job = Job {
            operation: Operation::Program,
            integer_type: U8,
            scalar: None,
            inputs: Inputs::Ciphertexts(&inputs),
            program: Some(&checked),
            compress: false,
        };
        assert!(matches!(
            evaluate1(&user_server_key(), &job),
            Err(EvalError::InvalidInput(_))
        ));
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
        let sum = evaluate1(
            &key,
            &Job {
                operation: Operation::Add,
                integer_type: U16,
                scalar: None,
                program: None,
                compress: false,
                inputs: Inputs::Ciphertexts(&first),
            },
        )
        .unwrap();
        let second = [sum, encrypt(ck, U16, 3)];
        let product = evaluate1(
            &key,
            &Job {
                operation: Operation::Multiply,
                integer_type: U16,
                scalar: None,
                program: None,
                compress: false,
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
            program: None,
            compress: false,
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
            let err = evaluate1(&key, &ciphertext_job(U16, &inputs)).unwrap_err();
            assert!(matches!(err, EvalError::InvalidInput(_)), "{err}");
        }

        // A well-formed ciphertext of another type.
        let inputs = [good.clone(), encrypt(ck, U8, 1)];
        assert!(matches!(
            evaluate1(&key, &ciphertext_job(U16, &inputs)),
            Err(EvalError::InvalidInput(_))
        ));
        // The wrong number of inputs.
        let inputs = [good.clone(), good.clone(), good];
        assert!(matches!(
            evaluate1(&key, &ciphertext_job(U16, &inputs)),
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
                program: None,
                compress: false,
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
        let out = evaluate1(&key, &job(&list, &crs, &metadata, Operation::Multiply)).unwrap();
        assert_eq!(decrypt(ck, I32.into(), &out), PlainValue::Int(-7_000_000));

        // A proof made for another key does not verify.
        let other = proof_metadata("key-2");
        assert!(matches!(
            evaluate1(&key, &job(&list, &crs, &other, Operation::Add)),
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
            program: None,
            compress: false,
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
            evaluate1(&user_server_key(), &job),
            Err(EvalError::InvalidInput(_))
        ));
        for bad in [&b"garbage"[..], &three[..three.len() / 2], &[]] {
            assert!(proven_input_count(bad, &crs.crs, U8).is_err());
        }
    }
}
