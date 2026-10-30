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
use crate::crypto::eval::proven_input_count;
use crate::crypto::params::{
    MAX_BATCH_JOBS, MAX_CIPHERTEXT_BYTES, MAX_INPUTS, MAX_JOB_INPUT_BYTES, MAX_PROVEN_LIST_BYTES,
};
use crate::crypto::proofs::Crs;
use crate::errors::AppError;
use crate::jobs::store::JobStore;
use crate::jobs::worker::JobNotifier;
use crate::middleware::quota::{consume_compute_quota, refund_compute_quota, QuotaCharge};
use actix_web::{http::header, web, HttpRequest, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use heaas_core::api::{
    BatchJobsRequest, BatchJobsResponse, CreateJobRequest, JobPage, JobStatus, JobSummary,
};
use heaas_core::Operation;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::sync::Arc;
use utoipa::IntoParams;
use uuid::Uuid;

const fn b64_len(bytes: u64) -> usize {
    (bytes as usize).div_ceil(3) * 4
}

/// Base64 length of the largest accepted ciphertext.
pub const MAX_INPUT_B64_LEN: usize = b64_len(MAX_CIPHERTEXT_BYTES);
const MAX_PROVEN_B64_LEN: usize = b64_len(MAX_PROVEN_LIST_BYTES);
/// Largest accepted `POST /jobs` body: the inputs (each base64-encoded, in
/// quotes and comma-separated) plus room for the other fields.
pub const MAX_SUBMIT_BODY_BYTES: usize = b64_len(MAX_JOB_INPUT_BYTES) + MAX_INPUTS * 3 + 64 * 1024;

const IDEMPOTENCY_KEY: &str = "Idempotency-Key";
const MAX_IDEMPOTENCY_KEY_LEN: usize = 255;

const SUMMARY_COLUMNS: &str = "id, status, operation, integer_type, result_type, input_count, \
     proven, scalar, program, key_id, attempts, error_message, input_bytes, result_bytes, created_at, \
     started_at, finished_at";

/// How long a client should wait before retrying a submission refused for load.
const RETRY_FULL_QUEUE_SECS: u64 = 10;
const RETRY_USER_LIMIT_SECS: u64 = 5;

const DEFAULT_PAGE_SIZE: u32 = 20;
const MAX_PAGE_SIZE: u32 = 100;

fn decode_b64(input: &str, limit: usize, which: &str, max_bytes: u64) -> Result<Vec<u8>, AppError> {
    if input.len() > limit {
        return Err(AppError::bad_request(format!(
            "{which} is larger than the {max_bytes}-byte limit"
        )));
    }
    general_purpose::STANDARD
        .decode(input)
        .map_err(|_| AppError::bad_request(format!("{which} is not valid base64")))
}

/// Decodes the ciphertext inputs, enforcing the count and size limits
/// (ciphertext validity is checked later against the caller's key).
fn decode_inputs(inputs: &[String]) -> Result<Vec<Vec<u8>>, AppError> {
    if inputs.len() > MAX_INPUTS {
        return Err(AppError::bad_request(format!(
            "At most {MAX_INPUTS} inputs, got {}",
            inputs.len()
        )));
    }
    let decoded = inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            decode_b64(
                input,
                MAX_INPUT_B64_LEN,
                &format!("Input {}", i + 1),
                MAX_CIPHERTEXT_BYTES,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let total: usize = decoded.iter().map(Vec::len).sum();
    if total as u64 > MAX_JOB_INPUT_BYTES {
        return Err(AppError::bad_request(format!(
            "The inputs are larger than the {MAX_JOB_INPUT_BYTES}-byte limit per job"
        )));
    }
    Ok(decoded)
}

/// A submission whose shape has been checked, ready to be stored.
struct Checked {
    /// The files to store: one per ciphertext, or the proven list.
    files: Vec<Vec<u8>>,
    input_count: usize,
    proven: bool,
    /// Normalized decimal scalar.
    scalar: Option<String>,
    result_type: heaas_core::ValueType,
    /// The program as JSON, for `operation = 'program'`.
    program_json: Option<String>,
}

/// Checks everything about a submission that does not need the caller's key:
/// input encoding and limits, the operand shape and the scalar's range.
async fn check_request(req: &CreateJobRequest, crs: &web::Data<Crs>) -> Result<Checked, AppError> {
    let ty = req.integer_type;
    let scalar = req
        .scalar
        .as_deref()
        .map(|s| ty.parse_value(s).map(|v| v.to_string()))
        .transpose()
        .map_err(|e| AppError::bad_request(format!("Invalid scalar: {e}")))?;
    let (files, input_count, proven) = match (&req.proven_inputs, req.inputs.is_empty()) {
        (Some(_), false) => {
            return Err(AppError::bad_request(
                "Send either inputs or proven_inputs, not both",
            ))
        }
        (None, true) => return Err(AppError::bad_request("The job has no inputs")),
        (None, false) => {
            let files = decode_inputs(&req.inputs)?;
            let count = files.len();
            (files, count, false)
        }
        (Some(list), true) => {
            let list = decode_b64(
                list,
                MAX_PROVEN_B64_LEN,
                "proven_inputs",
                MAX_PROVEN_LIST_BYTES,
            )?;
            let crs = crs.clone();
            let (count, list) = web::block(move || (proven_input_count(&list, &crs.crs, ty), list))
                .await
                .map_err(|e| AppError::internal(format!("checking proven inputs: {e}")))?;
            let count = count.map_err(|e| AppError::bad_request(e.to_string()))?;
            (vec![list], count, true)
        }
    };
    req.operation
        .check_operands(input_count, scalar.is_some())
        .map_err(AppError::bad_request)?;
    let (result_type, program_json) = match (req.operation, &req.program) {
        (Operation::Program, Some(program)) => {
            let checked = program
                .check(ty, input_count)
                .map_err(|e| AppError::bad_request(format!("Invalid program: {e}")))?;
            let json = serde_json::to_string(program)
                .map_err(|e| AppError::internal(format!("encoding the program: {e}")))?;
            (checked.result_type(), Some(json))
        }
        (Operation::Program, None) => {
            return Err(AppError::bad_request(
                "operation \"program\" needs a program",
            ))
        }
        (op, Some(_)) => {
            return Err(AppError::bad_request(format!(
                "Only operation \"program\" takes a program, not {op}"
            )))
        }
        (op, None) => (op.result_type(ty), None),
    };
    Ok(Checked {
        files,
        input_count,
        proven,
        scalar,
        result_type,
        program_json,
    })
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
/// a retry of the same request: every field (length-prefixed) and every input.
fn request_fingerprint(fields: &[&str], inputs: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    for part in fields {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
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

/// A submission that passed every check that needs no writes.
struct Prepared {
    request: CreateJobRequest,
    checked: Checked,
    fingerprint: String,
    idempotency_key: Option<String>,
}

/// Checks a submission (shape, inputs, the caller's key) and fingerprints it.
async fn prepare(
    pool: &SqlitePool,
    crs: &web::Data<Crs>,
    user_id: &str,
    request: CreateJobRequest,
    idempotency_key: Option<String>,
) -> Result<Prepared, AppError> {
    let checked = check_request(&request, crs).await?;
    let key: Option<(bool, bool)> = sqlx::query_as(
        "SELECT supports_proofs, public_key_sha256 IS NOT NULL FROM server_keys
         WHERE id = ? AND user_id = ?",
    )
    .bind(&request.key_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    let Some((supports_proofs, has_public_key)) = key else {
        return Err(AppError::not_found("Server key not found"));
    };
    if checked.proven && !supports_proofs {
        return Err(AppError::unprocessable(
            "This server key cannot take proven inputs: it was made before HE Engine 0.5. \
             Create a new key to use them.",
        ));
    }
    if checked.proven && !has_public_key {
        return Err(AppError::unprocessable(
            "Upload this key's public key (PUT /api/v1/keys/{id}/public-key) before sending proven inputs",
        ));
    }
    let fingerprint = request_fingerprint(
        &[
            &request.key_id,
            request.operation.as_str(),
            request.integer_type.as_str(),
            if checked.proven {
                "proven"
            } else {
                "ciphertexts"
            },
            checked.scalar.as_deref().unwrap_or(""),
            checked.program_json.as_deref().unwrap_or(""),
        ],
        &checked.files,
    );
    Ok(Prepared {
        request,
        checked,
        fingerprint,
        idempotency_key,
    })
}

/// The jobs earlier submitted with these submissions' idempotency keys: all of
/// them if every key was used for the same request, none if no key was used,
/// and 422 otherwise.
async fn replay(
    pool: &SqlitePool,
    user_id: &str,
    prepared: &[Prepared],
) -> Result<Option<Vec<JobSummary>>, AppError> {
    #[derive(sqlx::FromRow)]
    struct Earlier {
        id: String,
        request_sha256: Option<String>,
    }
    let mut found = Vec::new();
    for p in prepared {
        let Some(key) = &p.idempotency_key else {
            return Ok(None);
        };
        let earlier: Option<Earlier> = sqlx::query_as(
            "SELECT id, request_sha256 FROM jobs WHERE user_id = ? AND idempotency_key = ?",
        )
        .bind(user_id)
        .bind(key)
        .fetch_optional(pool)
        .await?;
        found.push(earlier.map(|e| (e, &p.fingerprint)));
    }
    if found.iter().all(Option::is_none) {
        return Ok(None);
    }
    let mut jobs = Vec::with_capacity(found.len());
    for entry in found {
        match entry {
            Some((earlier, fingerprint))
                if earlier.request_sha256.as_deref() == Some(fingerprint.as_str()) =>
            {
                jobs.push(
                    fetch_summary(pool, &earlier.id, user_id)
                        .await?
                        .ok_or_else(|| AppError::internal("idempotent job vanished"))?,
                );
            }
            _ => {
                return Err(AppError::unprocessable(format!(
                    "This {IDEMPOTENCY_KEY} was already used for a different request"
                )))
            }
        }
    }
    Ok(Some(jobs))
}

/// Why a job could not be queued.
enum Refusal {
    UserLimit(i64),
    QueueFull,
    DuplicateKey,
    Database(sqlx::Error),
}

/// Inserts one job unless the user or the whole queue is at capacity. The
/// capacity checks and the insert are one statement, so they cannot race; in a
/// transaction, each insert counts the ones before it.
async fn enqueue(
    conn: &mut sqlx::SqliteConnection,
    config: &Config,
    id: &str,
    user_id: &str,
    p: &Prepared,
) -> Result<(), Refusal> {
    let input_bytes: usize = p.checked.files.iter().map(Vec::len).sum();
    let inserted: Option<(String,)> = sqlx::query_as(
        "INSERT INTO jobs (id, user_id, status, input_data_b64, operation, integer_type,
                           result_type, input_count, proven, scalar, program, key_id,
                           input_bytes, idempotency_key, request_sha256)
         SELECT ?, ?, 'pending', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
         WHERE (SELECT COUNT(*) FROM jobs WHERE status IN ('pending', 'processing')) < ?
           AND (SELECT COUNT(*) FROM jobs
                WHERE user_id = ? AND status IN ('pending', 'processing')) < ?
         RETURNING id",
    )
    .bind(id)
    .bind(user_id)
    .bind(p.request.operation.as_str())
    .bind(p.request.integer_type)
    .bind(p.checked.result_type)
    .bind(p.checked.input_count as i64)
    .bind(p.checked.proven)
    .bind(&p.checked.scalar)
    .bind(&p.checked.program_json)
    .bind(&p.request.key_id)
    .bind(input_bytes as i64)
    .bind(&p.idempotency_key)
    .bind(&p.fingerprint)
    .bind(config.max_queued_jobs)
    .bind(user_id)
    .bind(config.max_active_jobs_per_user)
    .fetch_optional(&mut *conn)
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
    .fetch_one(&mut *conn)
    .await
    .map_err(Refusal::Database)?;
    Err(if active >= config.max_active_jobs_per_user {
        Refusal::UserLimit(active)
    } else {
        Refusal::QueueFull
    })
}

/// Inserts every job in one transaction: all are queued, or none.
async fn enqueue_all(
    pool: &SqlitePool,
    config: &Config,
    user_id: &str,
    ids: &[String],
    prepared: &[Prepared],
) -> Result<(), Refusal> {
    let mut tx = pool.begin().await.map_err(Refusal::Database)?;
    for (id, p) in ids.iter().zip(prepared) {
        enqueue(&mut tx, config, id, user_id, p).await?;
    }
    tx.commit().await.map_err(Refusal::Database)
}

/// Undoes the side effects of submissions that were not queued.
async fn abandon(
    pool: &SqlitePool,
    jobs: &web::Data<JobStore>,
    user_id: &str,
    charge: &QuotaCharge,
    job_ids: Vec<String>,
) {
    refund_compute_quota(pool, user_id, charge).await;
    let jobs = jobs.clone();
    let _ = web::block(move || job_ids.iter().for_each(|id| jobs.remove_logged(id))).await;
}

/// Charges, stores and queues the submissions, all of them or none. Returns
/// the jobs and whether they are earlier ones replayed for reused
/// idempotency keys.
async fn submit_all(
    pool: &SqlitePool,
    config: &Config,
    jobs: &web::Data<JobStore>,
    notifier: &JobNotifier,
    user_id: &str,
    prepared: Vec<Prepared>,
) -> Result<(Vec<JobSummary>, bool), AppError> {
    if let Some(earlier) = replay(pool, user_id, &prepared).await? {
        return Ok((earlier, true));
    }

    // Only accepted submissions are charged; polling and listing are free.
    let charge =
        consume_compute_quota(pool, user_id, config.daily_compute_quota, prepared.len()).await?;

    let ids: Vec<String> = prepared
        .iter()
        .map(|_| Uuid::new_v4().to_string())
        .collect();
    let stored = {
        let store = jobs.clone();
        let files: Vec<(String, Vec<Vec<u8>>)> = ids
            .iter()
            .cloned()
            .zip(prepared.iter().map(|p| p.checked.files.clone()))
            .collect();
        web::block(move || {
            files
                .iter()
                .try_for_each(|(id, files)| store.write_inputs(id, files))
        })
        .await
    };
    if !matches!(stored, Ok(Ok(()))) {
        abandon(pool, jobs, user_id, &charge, ids).await;
        return Err(AppError::service_unavailable(
            "Could not store the job; please retry",
            RETRY_FULL_QUEUE_SECS,
        ));
    }

    if let Err(refusal) = enqueue_all(pool, config, user_id, &ids, &prepared).await {
        abandon(pool, jobs, user_id, &charge, ids).await;
        return match refusal {
            Refusal::UserLimit(active) => Err(AppError::too_many_requests(
                format!(
                    "You have {active} jobs waiting or running{}. Wait for some to finish.",
                    if prepared.len() > 1 {
                        format!(
                            ", and the limit leaves no room for these {}",
                            prepared.len()
                        )
                    } else {
                        String::new()
                    }
                ),
                Some(RETRY_USER_LIMIT_SECS),
            )),
            Refusal::QueueFull => Err(AppError::service_unavailable(
                "The job queue is full; please retry shortly",
                RETRY_FULL_QUEUE_SECS,
            )),
            // A concurrent request with the same key won the race.
            Refusal::DuplicateKey => replay(pool, user_id, &prepared)
                .await?
                .map(|earlier| (earlier, true))
                .ok_or_else(|| AppError::internal("duplicate idempotency key not found")),
            Refusal::Database(e) => Err(e.into()),
        };
    }

    let mut summaries = Vec::with_capacity(ids.len());
    for id in &ids {
        notifier.job_queued();
        summaries.push(
            fetch_summary(pool, id, user_id)
                .await?
                .ok_or_else(|| AppError::internal("queued job vanished"))?,
        );
    }
    Ok((summaries, false))
}

fn crs_of(http: &HttpRequest) -> Result<&web::Data<Crs>, AppError> {
    // From the app data rather than as an extractor: handlers stay under
    // clippy's argument limit.
    http.app_data::<web::Data<Crs>>()
        .ok_or_else(|| AppError::internal("the proof CRS is not configured"))
}

/// `POST /api/v1/compute/jobs` — queue `operation` on the encrypted inputs.
///
/// Honours an `Idempotency-Key` header: resending the same request with the same
/// key returns the original job (with `Idempotent-Replayed: true`) instead of
/// queuing and charging a second one.
#[utoipa::path(post, path = "/compute/jobs", tag = "jobs", security(("bearer" = [])), request_body = heaas_core::api::CreateJobRequest, params(("Idempotency-Key" = Option<String>, Header, description = "1-255 visible ASCII characters. A retry with the same key and body returns the original job instead of queuing (and charging) another.")), responses((status = 202, description = "Queued (or, for a replayed idempotency key, the original job)", body = heaas_core::api::JobSummary, headers(("Location" = String, description = "The job"), ("Idempotent-Replayed" = bool, description = "`true` when this is the original job of a reused key"))), (status = 400, description = "Wrong number or shape of inputs, bad base64, a malformed proven list, a scalar out of range, an invalid program, or a bad Idempotency-Key", body = heaas_core::api::ErrorBody), (status = 404, description = "No such server key", body = heaas_core::api::ErrorBody), (status = 413, description = "Body too large", body = heaas_core::api::ErrorBody), (status = 422, description = "Unknown operation or type; proven inputs for a key without proof support or public key; or the Idempotency-Key was used for a different request", body = heaas_core::api::ErrorBody), (status = 429, description = "Daily quota used up, or too many jobs waiting; see `Retry-After`", body = heaas_core::api::ErrorBody), (status = 503, description = "The queue is full; see `Retry-After`", body = heaas_core::api::ErrorBody)))]
pub async fn submit_job(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    jobs: web::Data<JobStore>,
    notifier: web::Data<JobNotifier>,
    http: HttpRequest,
    req: web::Json<CreateJobRequest>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, AppError> {
    let user_id = user_id.into_inner();
    let pool = pool.get_ref();
    let key = idempotency_key(&http)?;
    let prepared = prepare(pool, crs_of(&http)?, &user_id, req.into_inner(), key).await?;
    let (mut queued, replayed) =
        submit_all(pool, &config, &jobs, &notifier, &user_id, vec![prepared]).await?;
    let job = queued
        .pop()
        .ok_or_else(|| AppError::internal("no job queued"))?;
    Ok(accepted(job, replayed))
}

/// `POST /api/v1/compute/jobs/batch` — queue several jobs at once, all or none.
///
/// With an `Idempotency-Key`, job *i* is keyed `<key>/<i>`: resending the batch
/// returns the original jobs.
#[utoipa::path(post, path = "/compute/jobs/batch", tag = "jobs", security(("bearer" = [])), request_body = heaas_core::api::BatchJobsRequest, params(("Idempotency-Key" = Option<String>, Header, description = "1-255 visible ASCII characters, for the whole batch. A retry with the same key and body returns the original jobs.")), responses((status = 202, description = "Every job queued (or, for a replayed idempotency key, the original jobs), in request order", body = heaas_core::api::BatchJobsResponse, headers(("Idempotent-Replayed" = bool, description = "`true` when these are the original jobs of a reused key"))), (status = 400, description = "An empty or oversized batch, or any job that would be refused on its own (the message names it)", body = heaas_core::api::ErrorBody), (status = 404, description = "A job names no server key of yours", body = heaas_core::api::ErrorBody), (status = 413, description = "Body too large: all inputs together are limited like one job's", body = heaas_core::api::ErrorBody), (status = 422, description = "As for one job", body = heaas_core::api::ErrorBody), (status = 429, description = "Not enough daily quota or active-job room for every job; nothing is queued", body = heaas_core::api::ErrorBody), (status = 503, description = "The queue is full; see `Retry-After`", body = heaas_core::api::ErrorBody)))]
pub async fn submit_batch(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    jobs: web::Data<JobStore>,
    notifier: web::Data<JobNotifier>,
    http: HttpRequest,
    req: web::Json<BatchJobsRequest>,
    user_id: web::ReqData<String>,
) -> Result<HttpResponse, AppError> {
    let user_id = user_id.into_inner();
    let pool = pool.get_ref();
    let requests = req.into_inner().jobs;
    if requests.is_empty() || requests.len() > MAX_BATCH_JOBS {
        return Err(AppError::bad_request(format!(
            "A batch has 1 to {MAX_BATCH_JOBS} jobs, not {}",
            requests.len()
        )));
    }
    let key = idempotency_key(&http)?;
    let crs = crs_of(&http)?;
    let mut prepared = Vec::with_capacity(requests.len());
    for (i, request) in requests.into_iter().enumerate() {
        let job_key = key.as_ref().map(|k| format!("{k}/{i}"));
        let p = prepare(pool, crs, &user_id, request, job_key)
            .await
            .map_err(|e| e.prefixed(&format!("Job {}: ", i + 1)))?;
        prepared.push(p);
    }
    // Each job's fingerprint covers the whole batch, so a key reused for a
    // different batch (even one sharing some jobs) is refused.
    let whole: Vec<Vec<u8>> = prepared
        .iter()
        .map(|p| p.fingerprint.clone().into_bytes())
        .collect();
    let batch = request_fingerprint(&["batch"], &whole);
    for (i, p) in prepared.iter_mut().enumerate() {
        p.fingerprint = format!("{batch}:{i}");
    }
    let total: usize = prepared
        .iter()
        .flat_map(|p| &p.checked.files)
        .map(Vec::len)
        .sum();
    if total as u64 > MAX_JOB_INPUT_BYTES {
        return Err(AppError::bad_request(format!(
            "The inputs of a batch are limited to {MAX_JOB_INPUT_BYTES} bytes together"
        )));
    }
    let (queued, replayed) =
        submit_all(pool, &config, &jobs, &notifier, &user_id, prepared).await?;
    let mut response = HttpResponse::Accepted();
    if replayed {
        response.insert_header(("Idempotent-Replayed", "true"));
    }
    Ok(response.json(BatchJobsResponse { jobs: queued }))
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
/// `application/octet-stream`: a `safe_serialize`d ciphertext of the job's
/// `result_type` (`FheBool` for comparisons).
#[utoipa::path(get, path = "/compute/jobs/{id}/result", tag = "jobs", security(("bearer" = [])), params(("id" = String, Path, description = "Job id")), responses((status = 200, description = "The encrypted result: a `safe_serialize`d ciphertext of the job's `result_type` (e.g. `FheUint16`, or `FheBool` for comparisons)", body = inline(crate::api::openapi::Binary), content_type = "application/octet-stream"), (status = 404, description = "No such job", body = heaas_core::api::ErrorBody), (status = 409, description = "The job has not completed", body = heaas_core::api::ErrorBody)))]
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
        assert_eq!(
            decode_inputs(&vec![ok.clone(); MAX_INPUTS]).unwrap().len(),
            MAX_INPUTS
        );

        assert!(decode_inputs(&vec![ok.clone(); MAX_INPUTS + 1]).is_err());
        assert!(decode_inputs(&[ok.clone(), "not base64!".into()]).is_err());
        assert!(decode_inputs(&[ok, "A".repeat(MAX_INPUT_B64_LEN + 4)]).is_err());

        // Each input within its limit, but too much in total.
        let big = general_purpose::STANDARD.encode(vec![0u8; MAX_CIPHERTEXT_BYTES as usize]);
        assert!(decode_inputs(&vec![big; 10]).is_err());
    }

    #[test]
    fn fingerprints_cover_every_field_and_input() {
        let inputs = [b"a".to_vec(), b"b".to_vec()];
        let base = request_fingerprint(&["k", "add", "u16"], &inputs);
        assert_eq!(base, request_fingerprint(&["k", "add", "u16"], &inputs));
        assert_ne!(base, request_fingerprint(&["k2", "add", "u16"], &inputs));
        assert_ne!(base, request_fingerprint(&["k", "max", "u16"], &inputs));
        assert_ne!(base, request_fingerprint(&["k", "add", "i16"], &inputs));
        assert_ne!(
            base,
            request_fingerprint(&["k", "add", "u16"], &[b"b".to_vec(), b"a".to_vec()])
        );
        // Length prefixes keep field boundaries unambiguous.
        assert_ne!(
            request_fingerprint(&["ka", "dd", "u16"], &inputs),
            request_fingerprint(&["k", "add", "u16"], &inputs)
        );
    }

    #[test]
    fn cursors_round_trip_and_reject_garbage() {
        let job = JobSummary {
            id: Uuid::new_v4().to_string(),
            status: JobStatus::Completed,
            operation: heaas_core::Operation::Add,
            integer_type: heaas_core::IntegerType::U16,
            result_type: heaas_core::ValueType::U16,
            input_count: 2,
            proven: false,
            scalar: None,
            program: None,
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
