//! Rust client for the Homomorphic Encryption Engine (HE Engine).
//!
//! Keys are generated and kept here ([`fhe`]); the server only receives the
//! compressed server (evaluation) key and ciphertexts, computes on them, and
//! returns encrypted results that only your client key can decrypt.
//!
//! The parameters and request/response types come from `heaas-core`, the
//! crate the server is built on, so the two cannot disagree. The `heaas`
//! command-line tool (`src/bin/heaas.rs`) is built on this crate.

mod client;
mod error;
pub mod fhe;

pub use client::{encode, Client};
pub use error::{Error, Result};
pub use heaas_core::{
    api, params, parse_expression, program, IntegerType, Operation, PlainValue, ValueType,
};
