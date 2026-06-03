use actix_web::{web, HttpResponse, Responder};
use sqlx::SqlitePool;
use uuid::Uuid;
use crate::db::models::{CreateJobRequest, Job, JobResponse};
use crate::crypto::engine::AppState;
use base64::{Engine as _, engine::general_purpose};
use crate::error::AppError;

pub async fn submit_job(
    pool: web::Data<SqlitePool>,
    state: web::Data<AppState>,
    req: web::Json<CreateJobRequest>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let job_id = Uuid::new_v4().to_string();
    let user_id_str = user_id.into_inner();

    if req.operation != "add" && req.operation != "multiply" {
        return Err(AppError { message: "Unsupported operation".to_string() });
    }

    sqlx::query!(
        "INSERT INTO jobs (id, user_id, status, input_data_b64, operation) VALUES (?, ?, 'pending', ?, ?)",
        job_id,
        user_id_str,
        req.input_data_b64,
        req.operation
    )
    .execute(pool.get_ref())
    .await?;

    let pool_clone = pool.clone();
    let state_clone = state.clone();
    let job_id_clone = job_id.clone();
    let input_b64 = req.input_data_b64.clone();
    let op = req.operation.clone();

    tokio::spawn(async move {
        process_job(pool_clone, state_clone, job_id_clone, input_b64, op).await;
    });

    Ok(HttpResponse::Accepted().json(JobResponse {
        id: job_id,
        status: "pending".to_string(),
        result_b64: None,
        error_message: None,
    }))
}

async fn process_job(
    pool: web::Data<SqlitePool>,
    state: web::Data<AppState>,
    job_id: String,
    input_b64: String,
    operation: String,
) {
    let _ = sqlx::query!(
        "UPDATE jobs SET status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        job_id
    )
    .execute(pool.get_ref())
    .await;

    let inputs: Vec<String> = match serde_json::from_str(&input_b64) {
        Ok(v) => v,
        Err(_) => {
            update_job_status(&pool, &job_id, "failed", None, Some("Invalid input format".to_string())).await;
            return;
        }
    };

    if inputs.len() != 2 {
        update_job_status(&pool, &job_id, "failed", None, Some("Expected 2 inputs".to_string())).await;
        return;
    }

    let ct1_data = match general_purpose::STANDARD.decode(&inputs[0]) {
        Ok(d) => d,
        Err(_) => {
            update_job_status(&pool, &job_id, "failed", None, Some("Invalid Base64 for input 1".to_string())).await;
            return;
        }
    };

    let ct2_data = match general_purpose::STANDARD.decode(&inputs[1]) {
        Ok(d) => d,
        Err(_) => {
            update_job_status(&pool, &job_id, "failed", None, Some("Invalid Base64 for input 2".to_string())).await;
            return;
        }
    };

    // Optimization: Accessing he_context directly from Arc without Mutex.
    // This allows multiple concurrent HE operations.
    let ctx = &state.he_context;
    
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
}

async fn update_job_status(
    pool: &web::Data<SqlitePool>,
    job_id: &str,
    status: &str,
    result: Option<String>,
    error: Option<String>,
) {
    let _ = sqlx::query!(
        "UPDATE jobs SET status = ?, result_b64 = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        status,
        result,
        error,
        job_id
    )
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
    let job = sqlx::query_as!(
        Job,
        "SELECT id, user_id, status, input_data_b64, operation, result_b64, error_message, created_at, updated_at FROM jobs WHERE id = ? AND user_id = ?",
        jid,
        uid
    )
    .fetch_optional(pool.get_ref())
    .await?;

    match job {
        Some(j) => Ok(HttpResponse::Ok().json(j)),
        None => Err(AppError { message: "Job not found".to_string() }),
    }
}
