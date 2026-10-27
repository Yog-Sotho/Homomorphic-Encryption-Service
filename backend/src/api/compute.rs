//! `/api/v1/compute/jobs`: homomorphic jobs evaluated under the caller's own key.
//!
//! The server never sees plaintext: inputs arrive encrypted under the caller's
//! client key, are evaluated with the caller's uploaded server key, and the
//! encrypted result is returned for the caller to decrypt.
//!
//! Submissions are queued durably (see [`crate::jobs`]) and answered with
//! `202 Accepted`; clients poll `GET /jobs/{id}` and then fetch
//! `GET /jobs/{id}/result`.

use crate::config::Config;
use crate::crypto::params::MAX_CIPHERTEXT_BYTES;
use crate::errors::AppError;
use crate::jobs::store::JobStore;
use crate::jobs::worker::JobNotifier;
use crate::jobs::INPUT_COUNT;
use crate::middleware::quota::{consume_compute_quota, refund_compute_quota, QuotaCharge};
use actix_web::{http::header, web, HttpRequest, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use heaas_core::api::{CreateJobRequest, JobPage, JobStatus, JobSummary};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::sync::Arc;
use utoipa::IntoParams;
use uuid::Uuid;

/// Base64 length of the largest accepted ciphertext.
pub const MAX_INPUT_B64_LEN: usize = (MAX_CIPHERTEXT_BYTES as usize).div_ceil(3) * 4;
/// Largest accepted `POST /jobs` body: the inputs plus room for the other fields.
pub const MAX_SUBMIT_BODY_BYTES: usize = INPUT_COUNT * MAX_INPUT_B64_LEN + 64 * 1024;

const IDEMPOTENCY_KEY: &str = "Idempotency-Key";
const MAX_IDEMPOTENCY_KEY_LEN: usize = 255;

const SUMMARY_COLUMNS: &str = "id, status, operation, key_id, attempts, error_message, \
     input_bytes, result_bytes, created_at, started_at, finished_at";

/// How long a client should wait before retrying a submission refused for load.
const RETRY_FULL_QUEUE_SECS: u64 = 10;
const RETRY_USER_LIMIT_SECS: u64 = 5;

const DEFAULT_PAGE_SIZE: u32 = 20;
const MAX_PAGE_SIZE: u32 = 100;

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

/// The optional `Idempotency-Key` header: 1–255 visible ASCII characters.
fn idempotency_key(req: &HttpRequest) -> Result<Option<String>, AppError> {
    let Some(value) = req.headers().get(IDEMPOTENCY_KEY) else {
        return Ok(None);
    };
    let key = value.to_str().unwrap_or_default();
    let valid = !key.is_empty()
        && key.len() <= MAX_IDEMPOTENCY_KEY_LEN
        && key.bytes().all(|b| b.is_ascii_graphic());
    if !valid {
        return Err(AppError::bad_request(format!(
            "{IDEMPOTENCY_KEY} must be 1-{MAX_IDEMPOTENCY_KEY_LEN} visible ASCII characters"
        )));
    }
    Ok(Some(key.to_string()))
}

/// Identifies a submission, so a reused idempotency key can be told apart from
/// a retry of the same request.
fn request_fingerprint(key_id: &str, operation: &str, inputs: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    for part in [key_id.as_bytes(), operation.as_bytes()] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    for input in inputs {
        hasher.update(Sha256::digest(input));
    }
    format!("{:x}", hasher.finalize())
}

async fn fetch_summary(
    pool: &SqlitePool,
    job_id: &str,
    user_id: &str,
) -> Result<Option<JobSummary>, AppError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {SUMMARY_COLUMNS} FROM jobs WHERE id = ? AND user_id = ?"
    ))
    .bind(job_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?)
}

fn accepted(job: JobSummary, replayed: bool) -> HttpResponse {
    let mut response = HttpResponse::Accepted();
    response.insert_header((header::LOCATION, format!("/api/v1/compute/jobs/{}", job.id)));
    if replayed {
        response.insert_header(("Idempotent-Replayed", "true"));
    }
    response.json(job)
}

/// Answers a submission whose idempotency key was already used: the original
/// job if the request is the same, 422 if it is not.
async fn replay(
    pool: &SqlitePool,
    user_id: &str,
    key: &str,
    fingerprint: &str,
) -> Result<Option<HttpResponse>, AppError> {
    #[derive(sqlx::FromRow)]
    struct Earlier {
        id: String,
        request_sha256: Option<String>,
    }
    let earlier: Option<Earlier> = sqlx::query_as(
        "SELECT id, request_sha256 FROM jobs WHERE user_id = ? AND idempotency_key = ?",
    )
    .bind(user_id)
    .bind(key)
    .fetch_optional(pool)
    .await?;
    let Some(earlier) = earlier else {
        return Ok(None);
    };
    if earlier.request_sha256.as_deref() != Some(fingerprint) {
        return Err(AppError::unprocessable(format!(
            "This {IDEMPOTENCY_KEY} was already used for a different request"
        )));
    }
    let job = fetch_summary(pool, &earlier.id, user_id)
        .await?
        .ok_or_else(|| AppError::internal("idempotent job vanished"))?;
    Ok(Some(accepted(job, true)))
}

/// Why a job could not be queued.
enum Refusal {
    UserLimit(i64),
    QueueFull,
    DuplicateKey,
    Database(sqlx::Error),
}

/// Inserts the job unless the user or the whole queue is at capacity. The
/// capacity checks and the insert are one statement, so they cannot race.
#[allow(clippy::too_many_arguments)]
async fn enqueue(
    pool: &SqlitePool,
    config: &Config,
    job_id: &str,
    user_id: &str,
    req: &CreateJobRequest,
    input_bytes: usize,
    idempotency_key: Option<&str>,
    fingerprint: &str,
) -> Result<(), Refusal> {
    let inserted: Option<(String,)> = sqlx::query_as(
        "INSERT INTO jobs (id, user_id, status, input_data_b64, operation, key_id,
                           input_bytes, idempotency_key, request_sha256)
         SELECT ?, ?, 'pending', '', ?, ?, ?, ?, ?
         WHERE (SELECT COUNT(*) FROM jobs WHERE status IN ('pending', 'processing')) < ?
           AND (SELECT COUNT(*) FROM jobs
                WHERE user_id = ? AND status IN ('pending', 'processing')) < ?
         RETURNING id",
    )
    .bind(job_id)
    .bind(user_id)
    .bind(req.operation.as_str())
    .bind(&req.key_id)
    .bind(input_bytes as i64)
    .bind(idempotency_key)
    .bind(fingerprint)
    .bind(config.max_queued_jobs)
    .bind(user_id)
    .bind(config.max_active_jobs_per_user)
    .fetch_optional(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db) if db.is_unique_violation() => Refusal::DuplicateKey,
        e => Refusal::Database(e),
    })?;
    if inserted.is_some() {
        return Ok(());
    }

    let (active,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM jobs WHERE user_id = ? AND status IN ('pending', 'processing')",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(Refusal::Database)?;
    Err(if active >= config.max_active_jobs_per_user {
        Refusal::UserLimit(active)
    } else {
        Refusal::QueueFull
    })
}

/// Undoes the side effects of a submission that was not queued.
async fn abandon(
    pool: &SqlitePool,
    jobs: &web::Data<JobStore>,
    user_id: &str,
    charge: &QuotaCharge,
    job_id: String,
) {
    refund_compute_quota(pool, user_id, charge).await;
    let jobs = jobs.clone();
    let _ = web::block(move || jobs.remove_logged(&job_id)).await;
}

/// `POST /api/v1/compute/jobs` — queue `operation(inputs[0], inputs[1])`.
///
/// Honours an `Idempotency-Key` header: resending the same request with the same
/// key returns the original job (with `Idempotent-Replayed: true`) instead of
/// queuing and charging a second one.
#[utoipa::path(post, path = "/compute/jobs", tag = "jobs", security(("bearer" = [])), request_body = heaas_core::api::CreateJobRequest, params(("Idempotency-Key" = Option<String>, Header, description = "1-255 visible ASCII characters. A retry with the same key and body returns the original job instead of queuing (and charging) another.")), responses((status = 202, description = "Queued (or, for a replayed idempotency key, the original job)", body = heaas_core::api::JobSummary, headers(("Location" = String, description = "The job"), ("Idempotent-Replayed" = bool, description = "`true` when this is the original job of a reused key"))), (status = 400, description = "Wrong number of inputs, bad base64 or a bad Idempotency-Key", body = heaas_core::api::ErrorBody), (status = 404, description = "No such server key", body = heaas_core::api::ErrorBody), (status = 413, description = "Body too large", body = heaas_core::api::ErrorBody), (status = 422, description = "Unknown operation, or the Idempotency-Key was used for a different request", body = heaas_core::api::ErrorBody), (status = 429, description = "Daily quota used up, or too many jobs waiting; see `Retry-After`", body = heaas_core::api::ErrorBody), (status = 503, description = "The queue is full; see `Retry-After`", body = heaas_core::api::ErrorBody)))]
pub async fn submit_job(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    jobs: web::Data<JobStore>,
    notifier: web::Data<JobNotifier>,
    http: HttpRequest,
    req: web::Json<CreateJobRequest>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, AppError> {
    let req = req.into_inner();
    let user_id = user_id.into_inner();
    let pool = pool.get_ref();
    let inputs = decode_inputs(&req.inputs)?;
    let idempotency_key = idempotency_key(&http)?;

    let owns_key: Option<(String,)> =
        sqlx::query_as("SELECT id FROM server_keys WHERE id = ? AND user_id = ?")
            .bind(&req.key_id)
            .bind(&user_id)
            .fetch_optional(pool)
            .await?;
    if owns_key.is_none() {
        return Err(AppError::not_found("Server key not found"));
    }

    let fingerprint = request_fingerprint(&req.key_id, req.operation.as_str(), &inputs);
    if let Some(key) = &idempotency_key {
        if let Some(response) = replay(pool, &user_id, key, &fingerprint).await? {
            return Ok(response);
        }
    }

    // Only accepted submissions are charged; polling and listing are free.
    let charge = consume_compute_quota(pool, &user_id, config.daily_compute_quota).await?;

    let job_id = Uuid::new_v4().to_string();
    let input_bytes = inputs.iter().map(Vec::len).sum();
    let stored = {
        let (jobs, job_id) = (jobs.clone(), job_id.clone());
        web::block(move || jobs.write_inputs(&job_id, &inputs)).await
    };
    if !matches!(stored, Ok(Ok(()))) {
        abandon(pool, &jobs, &user_id, &charge, job_id).await;
        return Err(AppError::service_unavailable(
            "Could not store the job; please retry",
            RETRY_FULL_QUEUE_SECS,
        ));
    }

    let queued = enqueue(
        pool,
        &config,
        &job_id,
        &user_id,
        &req,
        input_bytes,
        idempotency_key.as_deref(),
        &fingerprint,
    )
    .await;
    if let Err(refusal) = queued {
        abandon(pool, &jobs, &user_id, &charge, job_id).await;
        return match refusal {
            Refusal::UserLimit(active) => Err(AppError::too_many_requests(
                format!("You have {active} jobs waiting or running. Wait for some to finish."),
                Some(RETRY_USER_LIMIT_SECS),
            )),
            Refusal::QueueFull => Err(AppError::service_unavailable(
                "The job queue is full; please retry shortly",
                RETRY_FULL_QUEUE_SECS,
            )),
            // A concurrent request with the same key won the race.
            Refusal::DuplicateKey => {
                let key = idempotency_key.as_deref().unwrap_or_default();
                replay(pool, &user_id, key, &fingerprint)
                    .await?
                    .ok_or_else(|| AppError::internal("duplicate idempotency key not found"))
            }
            Refusal::Database(e) => Err(e.into()),
        };
    }

    notifier.job_queued();
    let job = fetch_summary(pool, &job_id, &user_id)
        .await?
        .ok_or_else(|| AppError::internal("queued job vanished"))?;
    Ok(accepted(job, false))
}

/// `GET /api/v1/compute/jobs/{id}`
#[utoipa::path(get, path = "/compute/jobs/{id}", tag = "jobs", security(("bearer" = [])), params(("id" = String, Path, description = "Job id")), responses((status = 200, description = "The job", body = heaas_core::api::JobSummary), (status = 404, description = "No such job", body = heaas_core::api::ErrorBody)))]
pub async fn get_job_status(
    pool: web::Data<SqlitePool>,
    job_id: web::Path<String>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    fetch_summary(pool.get_ref(), &job_id, &user_id)
        .await?
        .map(|job| HttpResponse::Ok().json(job))
        .ok_or_else(|| AppError::not_found("Job not found"))
}

/// `GET /api/v1/compute/jobs/{id}/result` — the encrypted result as
/// `application/octet-stream` (a `safe_serialize`d `FheUint16`).
#[utoipa::path(get, path = "/compute/jobs/{id}/result", tag = "jobs", security(("bearer" = [])), params(("id" = String, Path, description = "Job id")), responses((status = 200, description = "The encrypted result: a `safe_serialize`d `FheUint16`", body = inline(crate::api::openapi::Binary), content_type = "application/octet-stream"), (status = 404, description = "No such job", body = heaas_core::api::ErrorBody), (status = 409, description = "The job has not completed", body = heaas_core::api::ErrorBody)))]
pub async fn get_job_result(
    pool: web::Data<SqlitePool>,
    jobs: web::Data<JobStore>,
    job_id: web::Path<String>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let job_id = job_id.into_inner();
    // `result_b64` is only set on jobs finished before results moved to disk.
    #[derive(sqlx::FromRow)]
    struct ResultRow {
        status: JobStatus,
        result_b64: Option<String>,
    }
    let row: Option<ResultRow> =
        sqlx::query_as("SELECT status, result_b64 FROM jobs WHERE id = ? AND user_id = ?")
            .bind(&job_id)
            .bind(user_id.into_inner())
            .fetch_optional(pool.get_ref())
            .await?;
    let row = row.ok_or_else(|| AppError::not_found("Job not found"))?;
    if row.status != JobStatus::Completed {
        return Err(AppError::conflict(format!(
            "Job is {}; its result is available once it has completed",
            row.status
        )));
    }

    let bytes = match row.result_b64 {
        Some(b64) => general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| AppError::internal(format!("stored result is not base64: {e}")))?,
        None => {
            let jobs = jobs.clone();
            let id = job_id.clone();
            match web::block(move || jobs.read_result(&id)).await {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(AppError::not_found("Job result not found"))
                }
                Ok(Err(e)) => return Err(AppError::internal(format!("reading result: {e}"))),
                Err(e) => return Err(AppError::internal(format!("reading result: {e}"))),
            }
        }
    };
    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header((header::CACHE_CONTROL, "private, no-store"))
        .body(bytes))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// `next_cursor` of the previous page.
    cursor: Option<String>,
    /// Jobs per page (default 20).
    #[param(minimum = 1, maximum = 100)]
    limit: Option<u32>,
}

const CURSOR_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

fn encode_cursor(job: &JobSummary) -> String {
    let position = format!("{}|{}", job.created_at.format(CURSOR_TIME_FORMAT), job.id);
    general_purpose::URL_SAFE_NO_PAD.encode(position)
}

/// A cursor is the `(created_at, id)` of the last job on the previous page.
fn decode_cursor(cursor: &str) -> Result<(String, String), AppError> {
    let invalid = || AppError::bad_request("Invalid cursor");
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| invalid())?;
    let text = String::from_utf8(bytes).map_err(|_| invalid())?;
    let (created_at, id) = text.split_once('|').ok_or_else(invalid)?;
    chrono::NaiveDateTime::parse_from_str(created_at, CURSOR_TIME_FORMAT).map_err(|_| invalid())?;
    Uuid::parse_str(id).map_err(|_| invalid())?;
    Ok((created_at.to_string(), id.to_string()))
}

/// `GET /api/v1/compute/jobs?cursor=&limit=` — the caller's jobs, newest first.
#[utoipa::path(get, path = "/compute/jobs", tag = "jobs", security(("bearer" = [])), params(ListQuery), responses((status = 200, description = "The caller's jobs, newest first", body = heaas_core::api::JobPage), (status = 400, description = "Invalid cursor or limit", body = heaas_core::api::ErrorBody)))]
pub async fn list_jobs(
    pool: web::Data<SqlitePool>,
    query: web::Query<ListQuery>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(AppError::bad_request(format!(
            "limit must be between 1 and {MAX_PAGE_SIZE}"
        )));
    }
    let after = query.cursor.as_deref().map(decode_cursor).transpose()?;

    let mut jobs: Vec<JobSummary> = match &after {
        None => {
            sqlx::query_as(&format!(
                "SELECT {SUMMARY_COLUMNS} FROM jobs WHERE user_id = ?
                 ORDER BY created_at DESC, id DESC LIMIT ?"
            ))
            .bind(user_id.as_str())
            .bind(limit + 1)
            .fetch_all(pool.get_ref())
            .await?
        }
        Some((created_at, id)) => {
            sqlx::query_as(&format!(
                "SELECT {SUMMARY_COLUMNS} FROM jobs
                 WHERE user_id = ? AND (created_at < ? OR (created_at = ? AND id < ?))
                 ORDER BY created_at DESC, id DESC LIMIT ?"
            ))
            .bind(user_id.as_str())
            .bind(created_at)
            .bind(created_at)
            .bind(id)
            .bind(limit + 1)
            .fetch_all(pool.get_ref())
            .await?
        }
    };

    let next_cursor = if jobs.len() > limit as usize {
        jobs.truncate(limit as usize);
        jobs.last().map(encode_cursor)
    } else {
        None
    };
    Ok(HttpResponse::Ok().json(JobPage {
        data: jobs,
        next_cursor,
    }))
}

/// `DELETE /api/v1/compute/jobs/{id}` — removes a job that is not running, with
/// its stored ciphertexts.
#[utoipa::path(delete, path = "/compute/jobs/{id}", tag = "jobs", security(("bearer" = [])), params(("id" = String, Path, description = "Job id")), responses((status = 204, description = "Deleted with its ciphertexts"), (status = 404, description = "No such job", body = heaas_core::api::ErrorBody), (status = 409, description = "The job is running", body = heaas_core::api::ErrorBody)))]
pub async fn delete_job(
    pool: web::Data<SqlitePool>,
    jobs: web::Data<JobStore>,
    job_id: web::Path<String>,
    user_id: web::ReqData<String>,
) -> Result<impl Responder, AppError> {
    let job_id = job_id.into_inner();
    let deleted: Option<(String,)> = sqlx::query_as(
        "DELETE FROM jobs WHERE id = ? AND user_id = ? AND status != 'processing' RETURNING id",
    )
    .bind(&job_id)
    .bind(user_id.as_str())
    .fetch_optional(pool.get_ref())
    .await?;

    if deleted.is_none() {
        return Err(
            match fetch_summary(pool.get_ref(), &job_id, &user_id).await? {
                Some(_) => AppError::conflict("Job is running; delete it once it has finished"),
                None => AppError::not_found("Job not found"),
            },
        );
    }
    let jobs = jobs.clone();
    let _ = web::block(move || jobs.remove_logged(&job_id)).await;
    Ok(HttpResponse::NoContent().finish())
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

    #[test]
    fn fingerprints_cover_key_operation_and_every_input() {
        let inputs = [b"a".to_vec(), b"b".to_vec()];
        let base = request_fingerprint("k", "add", &inputs);
        assert_eq!(base, request_fingerprint("k", "add", &inputs));
        assert_ne!(base, request_fingerprint("k2", "add", &inputs));
        assert_ne!(base, request_fingerprint("k", "max", &inputs));
        assert_ne!(
            base,
            request_fingerprint("k", "add", &[b"b".to_vec(), b"a".to_vec()])
        );
        // Length prefixes keep field boundaries unambiguous.
        assert_ne!(
            request_fingerprint("ka", "dd", &inputs),
            request_fingerprint("k", "add", &inputs)
        );
    }

    #[test]
    fn cursors_round_trip_and_reject_garbage() {
        let job = JobSummary {
            id: Uuid::new_v4().to_string(),
            status: JobStatus::Completed,
            operation: heaas_core::Operation::Add,
            key_id: None,
            attempts: 1,
            error_message: None,
            input_bytes: None,
            result_bytes: None,
            created_at: chrono::NaiveDate::from_ymd_opt(2026, 10, 26)
                .unwrap()
                .and_hms_opt(12, 30, 5)
                .unwrap(),
            started_at: None,
            finished_at: None,
        };
        let (created_at, id) = decode_cursor(&encode_cursor(&job)).unwrap();
        assert_eq!((created_at.as_str(), id), ("2026-10-26 12:30:05", job.id));

        for bad in [
            "",
            "!!",
            "bm9waXBl",
            &general_purpose::URL_SAFE_NO_PAD.encode("x|y"),
        ] {
            assert!(decode_cursor(bad).is_err(), "{bad}");
        }
    }
}
