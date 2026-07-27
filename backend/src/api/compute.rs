use actix_web::{web, HttpResponse, Responder};
use sqlx::SqlitePool;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use crate::db::models::{CreateJobRequest, Job, JobResponse};
use crate::crypto::engine::{AppState, PLAIN_MODULUS};
use base64::{Engine as _, engine::general_purpose};
use crate::errors::AppError;

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

pub async fn sandbox_compute(
    state: web::Data<AppState>,
    req: web::Json<SandboxRequest>,
) -> Result<impl Responder, AppError> {
    if req.operation != "add" && req.operation != "multiply" {
        return Err(AppError::bad_request("Unsupported operation. Use 'add' or 'multiply'."));
    }
    if req.value1 >= PLAIN_MODULUS || req.value2 >= PLAIN_MODULUS {
        return Err(AppError::bad_request(
            format!("Values must be in the range 0–{}.", PLAIN_MODULUS - 1)
        ));
    }

    let ctx = state.he_pool.acquire();
    let v1 = req.value1;
    let v2 = req.value2;
    let op = req.operation.clone();

    // Offload CPU-heavy HE operations to a blocking thread to keep the async executor responsive.
    let (plaintext_result, result_ct) = tokio::task::spawn_blocking(move || {
        ctx.sandbox_compute_optimized(v1, v2, &op)
    })
    .await
    .map_err(|e| AppError::internal(format!("Task join error: {}", e)))?
    .map_err(|e| AppError::internal(format!("HE operation failed: {}", e)))?;

    let result_b64 = general_purpose::STANDARD.encode(&result_ct);

    Ok(HttpResponse::Ok().json(SandboxResponse {
        plaintext_result,
        result_b64,
    }))
}

pub async fn submit_job(
    pool: web::Data<SqlitePool>,
    state: web::Data<AppState>,
    req: web::Json<CreateJobRequest>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let job_id = Uuid::new_v4().to_string();
    let user_id_str = user_id.into_inner();

    if req.input_data_b64.len() > 2_000_000 {
        return Err(AppError::bad_request(
            "Input payload too large. Maximum length is 2,000,000 characters."
        ));
    }

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

    tokio::spawn(async move {
        match try_process_job(pool_clone.clone(), state_clone, job_id_clone.clone(), input_b64, op).await {
            Ok(()) => {}
            Err(e) => {
                log::error!("Job {} failed: {}", job_id_clone, e);
                update_job_status(&pool_clone, &job_id_clone, "failed", None,
                    Some(format!("Internal error: {}", e))).await;
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

    let ctx = state.he_pool.acquire();

    let result_data = tokio::task::spawn_blocking(move || {
        if operation == "add" {
            ctx.add_ciphertexts(&ct1_data, &ct2_data)
        } else {
            ctx.multiply_ciphertexts(&ct1_data, &ct2_data)
        }
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::HttpMessage;
    use actix_web::test::TestRequest;
    use actix_web::FromRequest;
    use actix_web::web::ReqData;
    use crate::crypto::engine::HeContextPool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_submit_job_length_validation() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        // Insert a mock user to satisfy foreign key constraint in the jobs table
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, 'user@example.com', '', 1)"
        )
        .bind("user_id_123")
        .execute(&pool)
        .await
        .unwrap();

        let he_pool = Arc::new(HeContextPool {
            contexts: vec![],
            counter: AtomicUsize::new(0),
        });
        let state = web::Data::new(AppState { he_pool });

        let pool_data = web::Data::new(pool);

        // 1. Valid input
        let req_valid = web::Json(CreateJobRequest {
            input_data_b64: "[\"ct1\", \"ct2\"]".to_string(),
            operation: "add".to_string(),
        });

        // Create http request and mock ReqData
        let http_req = TestRequest::default().to_http_request();
        http_req.extensions_mut().insert("user_id_123".to_string());
        let user_id = ReqData::<String>::extract(&http_req).await.unwrap();

        let res_valid = submit_job(pool_data.clone(), state.clone(), req_valid, user_id).await;
        assert!(res_valid.is_ok());

        // 2. Too long input (2,000,001 characters)
        let req_too_long = web::Json(CreateJobRequest {
            input_data_b64: "a".repeat(2_000_001),
            operation: "add".to_string(),
        });

        let http_req2 = TestRequest::default().to_http_request();
        http_req2.extensions_mut().insert("user_id_123".to_string());
        let user_id2 = ReqData::<String>::extract(&http_req2).await.unwrap();

        let res_too_long = submit_job(pool_data, state, req_too_long, user_id2).await;
        assert!(res_too_long.is_err());
        match res_too_long.err().unwrap() {
            AppError::BadRequest(msg) => {
                assert_eq!(msg, "Input payload too large. Maximum length is 2,000,000 characters.");
            }
            other => panic!("Expected BadRequest error, got {:?}", other),
        }
    }
}
