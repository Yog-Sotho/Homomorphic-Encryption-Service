//! What HE Engine clients and the server must agree on.
//!
//! - [`params`]: the TFHE-rs release and configuration keys and ciphertexts are made with.
//! - [`Operation`]: the homomorphic operations the service evaluates.
//! - [`api`]: request and response bodies of the HTTP API (`/api/v1`).
//!
//! The server and the Rust SDK both depend on this crate, so they cannot disagree
//! on parameters or wire formats.

pub mod api;
mod operation;
pub mod params;

pub use operation::Operation;
