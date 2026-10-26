use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::crypto::eval::Operation;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: NaiveDateTime,
    pub email_verified: bool,
    pub email_verify_token: Option<String>,
    pub password_reset_token: Option<String>,
    pub password_reset_expires_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Job {
    pub id: String,
    pub user_id: String,
    pub status: String,
    pub input_data_b64: String,
    pub operation: String,
    /// Server key the job is evaluated with; `None` for jobs from before per-user keys.
    pub key_id: Option<String>,
    pub result_b64: Option<String>,
    pub error_message: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    /// One of the caller's registered server keys (`POST /api/keys`).
    pub key_id: String,
    pub operation: Operation,
    /// Base64 (standard alphabet) of two `safe_serialize`d `FheUint16` ciphertexts.
    pub inputs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct JobResponse {
    pub id: String,
    pub status: String,
    pub result_b64: Option<String>,
    pub error_message: Option<String>,
}
