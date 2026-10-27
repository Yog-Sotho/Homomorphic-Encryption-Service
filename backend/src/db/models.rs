use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::crypto::eval::Operation;

/// A job as its owner sees it: metadata only, never ciphertexts or the owner's id.
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct JobSummary {
    pub id: String,
    /// `pending`, `processing`, `completed` or `failed`.
    pub status: String,
    pub operation: String,
    /// Server key the job is evaluated with; `None` once that key is deleted.
    pub key_id: Option<String>,
    /// Attempts started so far (a job is retried after internal errors).
    pub attempts: i64,
    pub error_message: Option<String>,
    /// Total size of the submitted ciphertexts.
    pub input_bytes: Option<i64>,
    /// Size of the encrypted result (`GET /api/compute/jobs/{id}/result`).
    pub result_bytes: Option<i64>,
    pub created_at: NaiveDateTime,
    pub started_at: Option<NaiveDateTime>,
    pub finished_at: Option<NaiveDateTime>,
}

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    /// One of the caller's registered server keys (`POST /api/keys`).
    pub key_id: String,
    pub operation: Operation,
    /// Base64 (standard alphabet) of two `safe_serialize`d `FheUint16` ciphertexts.
    pub inputs: Vec<String>,
}
