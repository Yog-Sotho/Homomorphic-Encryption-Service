//! `GET /api/v1/he/params`. The parameters themselves live in `heaas_core::params`,
//! shared with the Rust SDK.

use crate::config::Config;
use actix_web::{web, HttpResponse};
use heaas_core::api::HeParams;
pub use heaas_core::params::*;
use heaas_core::Operation;
use std::sync::Arc;

/// What a client needs to produce compatible keys and inputs.
#[utoipa::path(get, path = "/he/params", tag = "he", responses((status = 200, description = "Scheme, TFHE-rs version and limits", body = heaas_core::api::HeParams)))]
pub async fn get_params(config: web::Data<Arc<Config>>) -> HttpResponse {
    HttpResponse::Ok().json(HeParams {
        scheme: "TFHE (CGGI)".into(),
        library: "TFHE-rs".into(),
        tfhe_version: TFHE_VERSION.into(),
        config: "ConfigBuilder::default()".into(),
        integer_type: INTEGER_TYPE.into(),
        plaintext_modulus: PLAIN_MODULUS,
        operations: Operation::ALL.to_vec(),
        max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
        max_server_key_bytes: config.max_server_key_bytes,
        max_keys_per_user: config.max_keys_per_user,
    })
}
