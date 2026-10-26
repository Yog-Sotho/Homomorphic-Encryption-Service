//! `/api/compute/jobs`: homomorphic jobs evaluated under the caller's own key.
//!
//! The server never sees plaintext: inputs arrive encrypted under the caller's
//! client key, are evaluated with the caller's uploaded server key, and the
//! encrypted result is returned for the caller to decrypt.

use crate::config::Config;
use crate::crypto::eval::{evaluate, EvalError, Operation};
use crate::crypto::keys::{KeyStore, KeyStoreError};
use crate::crypto::params::MAX_CIPHERTEXT_BYTES;
use crate::db::models::{CreateJobRequest, Job, JobResponse};
use crate::errors::AppError;
use crate::middleware::quota::consume_compute_quota;
use actix_web::{web, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use sqlx::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

/// Each job takes exactly two operands.
const INPUT_COUNT: usize = 2;
/// Base64 length of the largest accepted ciphertext.
const MAX_INPUT_B64_LEN: usize = (MAX_CIPHERTEXT_BYTES as usize).div_ceil(3) * 4;

const JOB_COLUMNS: &str =
    "id, user_id, status, input_data_b64, operation, key_id, result_b64, error_message, created_at, updated_at";

/// Checks the request shape and decodes the inputs (ciphertext validity is
/// checked later against the caller's key).
fn decode_inputs(inputs: &[String]) -> Result<Vec<Vec<u8>>, AppError> {
    if inputs.len() != INPUT_COUNT {
        return Err(AppError::bad_request(format!(
            "Expected exactly {INPUT_COUNT} inputs, got {}",
            inputs.len()
        )));
    }
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            if input.len() > MAX_INPUT_B64_LEN {
                return Err(AppError::bad_request(format!(
                    "Input {} is larger than the {MAX_CIPHERTEXT_BYTES}-byte ciphertext limit",
                    i + 1
                )));
            }
            general_purpose::STANDARD
                .decode(input)
                .map_err(|_| AppError::bad_request(format!("Input {} is not valid base64", i + 1)))
        })
        .collect()
}

/// `POST /api/compute/jobs` — queue `operation(inputs[0], inputs[1])`.
pub async fn submit_job(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    store: web::Data<KeyStore>,
    req: web::Json<CreateJobRequest>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let req = req.into_inner();
    let user_id = user_id.into_inner();
    let inputs = decode_inputs(&req.inputs)?;

    let owns_key: Option<(String,)> =
        sqlx::query_as("SELECT id FROM server_keys WHERE id = ? AND user_id = ?")
            .bind(&req.key_id)
            .bind(&user_id)
            .fetch_optional(pool.get_ref())
            .await?;
    if owns_key.is_none() {
        return Err(AppError::not_found("Server key not found"));
    }

    // Only accepted submissions are charged; polling and listing are free.
    consume_compute_quota(pool.get_ref(), &user_id, config.daily_compute_quota).await?;

    let job_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO jobs (id, user_id, status, input_data_b64, operation, key_id)
         VALUES (?, ?, 'pending', ?, ?, ?)",
    )
    .bind(&job_id)
    .bind(&user_id)
    .bind(serde_json::to_string(&req.inputs).map_err(|e| AppError::internal(e.to_string()))?)
    .bind(req.operation.as_str())
    .bind(&req.key_id)
    .execute(pool.get_ref())
    .await?;

    let pool = pool.get_ref().clone();
    let id = job_id.clone();
    tokio::spawn(async move {
        run_job(&pool, store, &id, &req.key_id, req.operation, inputs).await;
    });

    Ok(HttpResponse::Accepted()
        .insert_header(("Location", format!("/api/compute/jobs/{job_id}")))
        .json(JobResponse {
            id: job_id,
            status: "pending".to_string(),
            result_b64: None,
            error_message: None,
        }))
}

/// Evaluates a job and records the outcome. Never panics the caller: every
/// failure ends as a `failed` job with a user-safe message.
async fn run_job(
    pool: &SqlitePool,
    store: web::Data<KeyStore>,
    job_id: &str,
    key_id: &str,
    operation: Operation,
    inputs: Vec<Vec<u8>>,
) {
    set_status(pool, job_id, "processing", None, None).await;

    let key_id = key_id.to_string();
    let outcome = web::block(move || -> Result<Vec<u8>, EvalError> {
        let key = store.load(&key_id).map_err(|e| match e {
            KeyStoreError::NotFound => {
                EvalError::InvalidInput("Server key no longer exists".into())
            }
            KeyStoreError::Invalid(m) => EvalError::Internal(format!("stored key is invalid: {m}")),
            KeyStoreError::Io(e) => EvalError::Internal(format!("key store: {e}")),
        })?;
        evaluate(&key, operation, &inputs[0], &inputs[1])
    })
    .await;

    match outcome {
        Ok(Ok(result)) => {
            let encoded = general_purpose::STANDARD.encode(result);
            set_status(pool, job_id, "completed", Some(encoded), None).await;
        }
        Ok(Err(EvalError::InvalidInput(message))) => {
            set_status(pool, job_id, "failed", None, Some(message)).await;
        }
        Ok(Err(EvalError::Internal(detail))) => {
            log::error!("Job {job_id} failed: {detail}");
            set_status(pool, job_id, "failed", None, Some("Internal error".into())).await;
        }
        Err(join_error) => {
            log::error!("Job {job_id} worker failed: {join_error}");
            set_status(pool, job_id, "failed", None, Some("Internal error".into())).await;
        }
    }
}

async fn set_status(
    pool: &SqlitePool,
    job_id: &str,
    status: &str,
    result: Option<String>,
    error: Option<String>,
) {
    let updated = sqlx::query(
        "UPDATE jobs SET status = ?, result_b64 = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?",
    )
    .bind(status)
    .bind(result)
    .bind(error)
    .bind(job_id)
    .execute(pool)
    .await;
    if let Err(e) = updated {
        log::error!("Failed to set job {job_id} to {status}: {e}");
    }
}

pub async fn get_job_status(
    pool: web::Data<SqlitePool>,
    job_id: web::Path<String>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let job: Option<Job> = sqlx::query_as(&format!(
        "SELECT {JOB_COLUMNS} FROM jobs WHERE id = ? AND user_id = ?"
    ))
    .bind(job_id.into_inner())
    .bind(user_id.into_inner())
    .fetch_optional(pool.get_ref())
    .await?;

    match job {
        Some(j) => Ok(HttpResponse::Ok().json(j)),
        None => Err(AppError::not_found("Job not found")),
    }
}

pub async fn list_jobs(
    pool: web::Data<SqlitePool>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let jobs: Vec<Job> = sqlx::query_as(&format!(
        "SELECT {JOB_COLUMNS} FROM jobs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50"
    ))
    .bind(user_id.into_inner())
    .fetch_all(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(jobs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_inputs_enforces_count_size_and_encoding() {
        let ok = general_purpose::STANDARD.encode(b"ciphertext");
        assert_eq!(decode_inputs(&[ok.clone(), ok.clone()]).unwrap().len(), 2);

        assert!(decode_inputs(std::slice::from_ref(&ok)).is_err());
        assert!(decode_inputs(&[ok.clone(), ok.clone(), ok.clone()]).is_err());
        assert!(decode_inputs(&[ok.clone(), "not base64!".into()]).is_err());
        assert!(decode_inputs(&[ok, "A".repeat(MAX_INPUT_B64_LEN + 4)]).is_err());
    }
}
