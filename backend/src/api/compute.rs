use actix_web::{web, HttpResponse, Responder};
use sqlx::SqlitePool;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use crate::db::models::{CreateJobRequest, Job, JobResponse};
use crate::crypto::engine::AppState;
use base64::{Engine as _, engine::general_purpose};
use crate::errors::AppError;

// ---------------------------------------------------------------------------
// Sandbox endpoint (C9)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SandboxRequest {
    pub value1: u64,
    pub value2: u64,
    pub operation: String,
}

#[derive(Serialize)]
pub struct SandboxResponse {
    pub plaintext_result: u64,
    pub result_b64: String,
}

/// POST /api/compute/sandbox
///
/// Accepts plaintext u64 values, encrypts them with the HE engine, performs
/// the requested operation on the ciphertexts, decrypts, and returns both the
/// plaintext result and the Base64-encoded raw ciphertext bytes.
pub async fn sandbox_compute(
    state: web::Data<AppState>,
    req: web::Json<SandboxRequest>,
) -> Result<impl Responder, AppError> {
    if req.operation != "add" && req.operation != "multiply" {
        return Err(AppError::bad_request("Unsupported operation. Use 'add' or 'multiply'."));
    }

    let ctx_arc = state.he_pool.acquire();
    let ctx = ctx_arc.lock().await;

    let ct1 = ctx.encrypt_batch(&[req.value1])
        .map_err(|e| AppError::internal(format!("Encrypt value1: {}", e)))?;
    let ct2 = ctx.encrypt_batch(&[req.value2])
        .map_err(|e| AppError::internal(format!("Encrypt value2: {}", e)))?;

    let result_ct = if req.operation == "add" {
        ctx.add_ciphertexts(&ct1, &ct2)
    } else {
        ctx.multiply_ciphertexts(&ct1, &ct2)
    }
    .map_err(|e| AppError::internal(format!("HE operation failed: {}", e)))?;

    let decrypted = ctx.decrypt_batch(&result_ct)
        .map_err(|e| AppError::internal(format!("Decrypt failed: {}", e)))?;

    let plaintext_result = decrypted.into_iter().next().unwrap_or(0);
    let result_b64 = general_purpose::STANDARD.encode(&result_ct);

    Ok(HttpResponse::Ok().json(SandboxResponse {
        plaintext_result,
        result_b64,
    }))
}

// ---------------------------------------------------------------------------
// Async job queue endpoints
// ---------------------------------------------------------------------------

pub async fn submit_job(
    pool: web::Data<SqlitePool>,
    state: web::Data<AppState>,
    req: web::Json<CreateJobRequest>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let job_id = Uuid::new_v4().to_string();
    let user_id_str = user_id.into_inner();

    if req.operation != "add" && req.operation != "multiply" {
        return Err(AppError::bad_request("Unsupported operation. Use 'add' or 'multiply'."));
    }

    sqlx::query(
        "INSERT INTO jobs (id, user_id, status, input_data_b64, operation) VALUES (?, ?, 'pending', ?, ?)",
    )
    .bind(&job_id)
    .bind(&user_id_str)
    .bind(&req.input_data_b64)
    .bind(&req.operation)
    .execute(pool.get_ref())
    .await?;

    let pool_clone = pool.clone();
    let state_clone = state.clone();
    let job_id_clone = job_id.clone();
    let input_b64 = req.input_data_b64.clone();
    let op = req.operation.clone();

    // B5 — wrap the spawn in a panic-safe handler that logs errors and updates
    // the job status to 'failed' if the inner work returns Err.
    tokio::spawn(async move {
        match try_process_job(pool_clone.clone(), state_clone, job_id_clone.clone(), input_b64, op).await {
            Ok(()) => {}
            Err(e) => {
                log::error!("Job {} failed: {}", job_id_clone, e);
                update_job_status(
                    &pool_clone,
                    &job_id_clone,
                    "failed",
                    None,
                    Some(format!("Internal error: {}", e)),
                )
                .await;
            }
        }
    });

    Ok(HttpResponse::Accepted().json(JobResponse {
        id: job_id,
        status: "pending".to_string(),
        result_b64: None,
        error_message: None,
    }))
}

/// Inner function that returns a Result so errors can be caught by the spawn wrapper.
async fn try_process_job(
    pool: web::Data<SqlitePool>,
    state: web::Data<AppState>,
    job_id: String,
    input_b64: String,
    operation: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    sqlx::query(
        "UPDATE jobs SET status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    )
    .bind(&job_id)
    .execute(pool.get_ref())
    .await?;

    let inputs: Vec<String> = serde_json::from_str(&input_b64)
        .map_err(|_| "Invalid input format")?;

    if inputs.len() != 2 {
        update_job_status(&pool, &job_id, "failed", None, Some("Expected 2 inputs".to_string())).await;
        return Ok(());
    }

    let ct1_data = match general_purpose::STANDARD.decode(&inputs[0]) {
        Ok(d) => d,
        Err(_) => {
            update_job_status(&pool, &job_id, "failed", None, Some("Invalid Base64 for input 1".to_string())).await;
            return Ok(());
        }
    };

    let ct2_data = match general_purpose::STANDARD.decode(&inputs[1]) {
        Ok(d) => d,
        Err(_) => {
            update_job_status(&pool, &job_id, "failed", None, Some("Invalid Base64 for input 2".to_string())).await;
            return Ok(());
        }
    };

    let ctx_arc = state.he_pool.acquire();
    let ctx = ctx_arc.lock().await;

    let result_data = if operation == "add" {
        ctx.add_ciphertexts(&ct1_data, &ct2_data)
    } else {
        ctx.multiply_ciphertexts(&ct1_data, &ct2_data)
    };

    match result_data {
        Ok(data) => {
            let result_b64 = general_purpose::STANDARD.encode(&data);
            update_job_status(&pool, &job_id, "completed", Some(result_b64), None).await;
        }
        Err(e) => {
            update_job_status(&pool, &job_id, "failed", None, Some(format!("HE Error: {}", e))).await;
        }
    }

    Ok(())
}

async fn update_job_status(
    pool: &web::Data<SqlitePool>,
    job_id: &str,
    status: &str,
    result: Option<String>,
    error: Option<String>,
) {
    let _ = sqlx::query(
        "UPDATE jobs SET status = ?, result_b64 = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    )
    .bind(status)
    .bind(result)
    .bind(error)
    .bind(job_id)
    .execute(pool.get_ref())
    .await;
}

pub async fn get_job_status(
    pool: web::Data<SqlitePool>,
    job_id: web::Path<String>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let jid = job_id.into_inner();
    let uid = user_id.into_inner();

    let job: Option<Job> = sqlx::query_as(
        "SELECT id, user_id, status, input_data_b64, operation, result_b64, error_message, created_at, updated_at \
         FROM jobs WHERE id = ? AND user_id = ?",
    )
    .bind(&jid)
    .bind(&uid)
    .fetch_optional(pool.get_ref())
    .await?;

    match job {
        Some(j) => Ok(HttpResponse::Ok().json(j)),
        None => Err(AppError::not_found("Job not found")),
    }
}

/// GET /api/compute/jobs — list the most recent 50 jobs for the authenticated user.
pub async fn list_jobs(
    pool: web::Data<SqlitePool>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let uid = user_id.into_inner();
    let jobs: Vec<Job> = sqlx::query_as(
        "SELECT id, user_id, status, input_data_b64, operation, result_b64, error_message, created_at, updated_at \
         FROM jobs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
    )
    .bind(&uid)
    .fetch_all(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(jobs))
}
