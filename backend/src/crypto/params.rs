//! `GET /api/v1/he/params` and `GET /api/v1/he/crs`. The parameters themselves
//! live in `heaas_core::params`, shared with the Rust SDK.

use crate::config::Config;
use crate::crypto::proofs::Crs;
use actix_web::{http::header, web, HttpRequest, HttpResponse};
use heaas_core::api::{HeParams, ProofParams};
pub use heaas_core::params::*;
use heaas_core::{IntegerType, Operation};
use std::sync::Arc;

/// Prefix of [`proof_metadata`]: the part before the key id.
const PROOF_METADATA_PREFIX: &str = "he-engine/proof/v1/";

/// What a client needs to produce compatible keys and inputs.
#[utoipa::path(get, path = "/he/params", tag = "he", responses((status = 200, description = "Scheme, TFHE-rs version and limits", body = heaas_core::api::HeParams)))]
pub async fn get_params(config: web::Data<Arc<Config>>, crs: web::Data<Crs>) -> HttpResponse {
    HttpResponse::Ok().json(HeParams {
        scheme: "TFHE (CGGI)".into(),
        library: "TFHE-rs".into(),
        tfhe_version: TFHE_VERSION.into(),
        config: format!("ConfigBuilder::default() + {PUBLIC_KEY_PARAMETERS_NAME}"),
        integer_type: DEFAULT_INTEGER_TYPE.tfhe_name().into(),
        plaintext_modulus: 1 << DEFAULT_INTEGER_TYPE.bits(),
        integer_types: IntegerType::ALL.to_vec(),
        operations: Operation::ALL.to_vec(),
        max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
        max_inputs: MAX_INPUTS,
        max_job_input_bytes: MAX_JOB_INPUT_BYTES,
        max_batch_jobs: MAX_BATCH_JOBS,
        max_program_steps: MAX_PROGRAM_STEPS,
        max_program_outputs: MAX_PROGRAM_OUTPUTS,
        max_table_entries: MAX_TABLE_ENTRIES,
        max_server_key_bytes: config.max_server_key_bytes,
        max_keys_per_user: config.max_keys_per_user,
        proofs: Some(ProofParams {
            crs_sha256: crs.sha256.clone(),
            max_bits: MAX_PROVEN_BITS,
            max_list_bytes: MAX_PROVEN_LIST_BYTES,
            max_public_key_bytes: MAX_PUBLIC_KEY_BYTES,
            metadata_prefix: PROOF_METADATA_PREFIX.into(),
        }),
    })
}

/// The CRS proven inputs are made against, as `application/octet-stream`.
#[utoipa::path(get, path = "/he/crs", tag = "he", responses((status = 200, description = "A `safe_serialize`d (compressed) TFHE-rs `CompactPkeCrs`; its SHA-256 is `proofs.crs_sha256` of `/he/params`", body = inline(crate::api::openapi::Binary), content_type = "application/octet-stream", headers(("ETag" = String, description = "The quoted SHA-256"))), (status = 304, description = "Unchanged since the `If-None-Match` ETag")))]
pub async fn get_crs(crs: web::Data<Crs>, req: HttpRequest) -> HttpResponse {
    let etag = format!("\"{}\"", crs.sha256);
    let cached = req
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|tag| tag.trim() == etag));
    let mut response = if cached {
        HttpResponse::NotModified()
    } else {
        HttpResponse::Ok()
    };
    response
        .insert_header((header::ETAG, etag))
        .insert_header((header::CACHE_CONTROL, "public, max-age=3600"));
    if cached {
        response.finish()
    } else {
        response
            .content_type("application/octet-stream")
            .body(crs.bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_advertised_metadata_prefix_is_what_proofs_use() {
        assert_eq!(
            proof_metadata("k-1"),
            format!("{PROOF_METADATA_PREFIX}k-1").into_bytes()
        );
    }
}
