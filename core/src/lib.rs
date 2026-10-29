//! What HE Engine clients and the server must agree on.
//!
//! - [`params`]: the TFHE-rs release and configuration keys and ciphertexts are made with.
//! - [`Operation`] and [`IntegerType`]: what the service computes, on which types,
//!   and the plaintext results clients check decryptions against.
//! - [`api`]: request and response bodies of the HTTP API (`/api/v1`).
//!
//! The server and the Rust SDK both depend on this crate, so they cannot disagree
//! on parameters or wire formats.

pub mod api;
mod operation;
pub mod params;
mod types;

pub use operation::Operation;
pub use types::{IntegerType, PlainValue, ValueType};
