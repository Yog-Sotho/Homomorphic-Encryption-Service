//! Request and response bodies of the HTTP API (`/api/v1`).
//!
//! Timestamps are UTC without an offset (`2026-10-27T10:00:00`).

use crate::Operation;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// Every error response: `{"error": {"code": "...", "message": "..."}}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ErrorDetail {
    /// Stable, machine-readable reason; one of [`error_codes`]. New codes may be
    /// added, so clients should fall back on the HTTP status for unknown ones.
    #[cfg_attr(feature = "openapi", schema(example = "not_found"))]
    pub code: String,
    /// Human-readable explanation, safe to show to the user.
    pub message: String,
}

/// The `code` values of [`ErrorDetail`].
pub mod error_codes {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const FORBIDDEN: &str = "forbidden";
    pub const NOT_FOUND: &str = "not_found";
    pub const METHOD_NOT_ALLOWED: &str = "method_not_allowed";
    pub const CONFLICT: &str = "conflict";
    pub const PAYLOAD_TOO_LARGE: &str = "payload_too_large";
    pub const UNSUPPORTED_MEDIA_TYPE: &str = "unsupported_media_type";
    pub const UNPROCESSABLE: &str = "unprocessable";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const UNAVAILABLE: &str = "unavailable";
    pub const INTERNAL: &str = "internal";
}

/// A plain confirmation, e.g. after registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct MessageResponse {
    pub message: String,
}

/// `GET /api/v1/he/params`: what a client needs to make compatible keys and inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct HeParams {
    #[cfg_attr(feature = "openapi", schema(example = "TFHE (CGGI)"))]
    pub scheme: String,
    #[cfg_attr(feature = "openapi", schema(example = "TFHE-rs"))]
    pub library: String,
    /// Clients must use exactly this TFHE-rs release.
    #[cfg_attr(feature = "openapi", schema(example = "1.8.2"))]
    pub tfhe_version: String,
    #[cfg_attr(feature = "openapi", schema(example = "ConfigBuilder::default()"))]
    pub config: String,
    #[cfg_attr(feature = "openapi", schema(example = "FheUint16"))]
    pub integer_type: String,
    pub plaintext_modulus: u64,
    pub operations: Vec<Operation>,
    pub max_ciphertext_bytes: u64,
    pub max_server_key_bytes: u64,
    pub max_keys_per_user: i64,
}

// ── Accounts ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct UserPublic {
    pub id: String,
    pub email: String,
    pub created_at: NaiveDateTime,
}

/// A signed-in session. The refresh token is not here: it is set as the
/// `HttpOnly` cookie `heaas_refresh` (path `/api/v1/auth`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct AuthResponse {
    /// Bearer token for API calls.
    pub token: String,
    /// Seconds until `token` expires.
    pub expires_in: i64,
    pub user: UserPublic,
}

// ── Keys ────────────────────────────────────────────────────────────────────

/// A registered (compressed) server key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ServerKeyInfo {
    pub id: String,
    /// Lower-case hex SHA-256 of the uploaded bytes.
    pub sha256: String,
    pub size_bytes: i64,
    pub created_at: NaiveDateTime,
}

// ── Jobs ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type), sqlx(rename_all = "lowercase"))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum JobStatus {
    Pending,
    Processing,
    Completed,
    Failed,
}

impl JobStatus {
    pub fn is_finished(self) -> bool {
        matches!(self, JobStatus::Completed | JobStatus::Failed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            JobStatus::Pending => "pending",
            JobStatus::Processing => "processing",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
        }
    }
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `POST /api/v1/compute/jobs`: compute `operation(inputs[0], inputs[1])`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct CreateJobRequest {
    /// One of the caller's registered server keys.
    pub key_id: String,
    pub operation: Operation,
    /// Standard base64 of exactly two `safe_serialize`d `FheUint16` ciphertexts,
    /// encrypted with the client key that belongs to `key_id`.
    pub inputs: Vec<String>,
}

/// A job as its owner sees it: metadata only, never ciphertexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct JobSummary {
    pub id: String,
    pub status: JobStatus,
    pub operation: Operation,
    /// The server key the job is evaluated with; `None` once that key is deleted.
    pub key_id: Option<String>,
    /// Attempts started so far (internal errors are retried).
    pub attempts: i64,
    /// Why the job failed, if it did.
    pub error_message: Option<String>,
    /// Total size of the submitted ciphertexts.
    pub input_bytes: Option<i64>,
    /// Size of the encrypted result (`GET /api/v1/compute/jobs/{id}/result`).
    pub result_bytes: Option<i64>,
    pub created_at: NaiveDateTime,
    pub started_at: Option<NaiveDateTime>,
    pub finished_at: Option<NaiveDateTime>,
}

/// One page of `GET /api/v1/compute/jobs`, newest first.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct JobPage {
    pub data: Vec<JobSummary>,
    /// Pass as `cursor` for the next (older) page; `None` on the last page.
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_summaries_use_the_wire_names_clients_expect() {
        let json = serde_json::json!({
            "id": "j", "status": "completed", "operation": "multiply", "key_id": null,
            "attempts": 1, "error_message": null, "input_bytes": 264000,
            "result_bytes": 132000, "created_at": "2026-10-27T10:00:00",
            "started_at": null, "finished_at": "2026-10-27T10:00:02"
        });
        let job: JobSummary = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            (job.status, job.operation),
            (JobStatus::Completed, Operation::Multiply)
        );
        assert!(job.status.is_finished());
        assert_eq!(serde_json::to_value(&job).unwrap(), json);
    }

    #[test]
    fn errors_have_a_code_and_a_message() {
        let body: ErrorBody =
            serde_json::from_str(r#"{"error":{"code":"rate_limited","message":"Slow down"}}"#)
                .unwrap();
        assert_eq!(body.error.code, error_codes::RATE_LIMITED);
        assert_eq!(body.error.message, "Slow down");
    }
}
