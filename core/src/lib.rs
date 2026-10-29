//! What HE Engine clients and the server must agree on.
//!
//! - [`params`]: the TFHE-rs release and configuration keys and ciphertexts are made with.
//! - [`Operation`] and [`IntegerType`]: what the service computes, on which types,
//!   and the plaintext results clients check decryptions against.
//! - [`program`]: several operations in one job, and [`parse_expression`] for an
//!   expression syntax that compiles to programs.
//! - [`api`]: request and response bodies of the HTTP API (`/api/v1`).
//!
//! The server and the Rust SDK both depend on this crate, so they cannot disagree
//! on parameters or wire formats.

pub mod api;
mod expression;
mod operation;
pub mod params;
pub mod program;
mod types;

pub use expression::{parse_expression, Compiled};
pub use operation::Operation;
pub use types::{IntegerType, PlainValue, ValueType};

#[doc(hidden)]
pub use tfhe as __tfhe;

/// Runs `$body` with `$fhe`, `$clear` and `$conformance` naming the TFHE-rs
/// type, the Rust integer type and the ciphertext conformance parameters of
/// `$ty` (an [`IntegerType`]): the one table the server and the SDK share.
///
/// ```
/// use heaas_core::{with_fhe_type, IntegerType};
/// let bits = with_fhe_type!(IntegerType::I32, Fhe, Clear, Conformance => Clear::BITS);
/// assert_eq!(bits, 32);
/// ```
#[macro_export]
macro_rules! with_fhe_type {
    ($ty:expr, $fhe:ident, $clear:ident, $conformance:ident => $body:expr) => {
        match $ty {
            $crate::IntegerType::U8 => {
                #[allow(dead_code)]
                type $fhe = $crate::__tfhe::FheUint8;
                #[allow(dead_code)]
                type $clear = u8;
                #[allow(dead_code)]
                type $conformance = $crate::__tfhe::FheUint8ConformanceParams;
                $body
            }
            $crate::IntegerType::U16 => {
                #[allow(dead_code)]
                type $fhe = $crate::__tfhe::FheUint16;
                #[allow(dead_code)]
                type $clear = u16;
                #[allow(dead_code)]
                type $conformance = $crate::__tfhe::FheUint16ConformanceParams;
                $body
            }
            $crate::IntegerType::U32 => {
                #[allow(dead_code)]
                type $fhe = $crate::__tfhe::FheUint32;
                #[allow(dead_code)]
                type $clear = u32;
                #[allow(dead_code)]
                type $conformance = $crate::__tfhe::FheUint32ConformanceParams;
                $body
            }
            $crate::IntegerType::U64 => {
                #[allow(dead_code)]
                type $fhe = $crate::__tfhe::FheUint64;
                #[allow(dead_code)]
                type $clear = u64;
                #[allow(dead_code)]
                type $conformance = $crate::__tfhe::FheUint64ConformanceParams;
                $body
            }
            $crate::IntegerType::I8 => {
                #[allow(dead_code)]
                type $fhe = $crate::__tfhe::FheInt8;
                #[allow(dead_code)]
                type $clear = i8;
                #[allow(dead_code)]
                type $conformance = $crate::__tfhe::FheInt8ConformanceParams;
                $body
            }
            $crate::IntegerType::I16 => {
                #[allow(dead_code)]
                type $fhe = $crate::__tfhe::FheInt16;
                #[allow(dead_code)]
                type $clear = i16;
                #[allow(dead_code)]
                type $conformance = $crate::__tfhe::FheInt16ConformanceParams;
                $body
            }
            $crate::IntegerType::I32 => {
                #[allow(dead_code)]
                type $fhe = $crate::__tfhe::FheInt32;
                #[allow(dead_code)]
                type $clear = i32;
                #[allow(dead_code)]
                type $conformance = $crate::__tfhe::FheInt32ConformanceParams;
                $body
            }
            $crate::IntegerType::I64 => {
                #[allow(dead_code)]
                type $fhe = $crate::__tfhe::FheInt64;
                #[allow(dead_code)]
                type $clear = i64;
                #[allow(dead_code)]
                type $conformance = $crate::__tfhe::FheInt64ConformanceParams;
                $body
            }
        }
    };
}
