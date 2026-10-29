//! Request and response bodies of the HTTP API (`/api/v1`).
//!
//! Timestamps are UTC without an offset (`2026-10-27T10:00:00`).

use crate::program::Program;
use crate::{IntegerType, Operation, ValueType};
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

    /// The code for an HTTP error status, for responses that carry no envelope.
    pub fn for_status(status: u16) -> &'static str {
        match status {
            401 => UNAUTHORIZED,
            403 => FORBIDDEN,
            404 => NOT_FOUND,
            405 => METHOD_NOT_ALLOWED,
            409 => CONFLICT,
            413 => PAYLOAD_TOO_LARGE,
            415 => UNSUPPORTED_MEDIA_TYPE,
            422 => UNPROCESSABLE,
            429 => RATE_LIMITED,
            503 => UNAVAILABLE,
            500..=599 => INTERNAL,
            _ => BAD_REQUEST,
        }
    }
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
    #[cfg_attr(
        feature = "openapi",
        schema(
            example = "ConfigBuilder::default() + PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128"
        )
    )]
    pub config: String,
    /// The TFHE-rs type of the default `integer_type` (`u16`).
    #[cfg_attr(feature = "openapi", schema(example = "FheUint16"))]
    pub integer_type: String,
    /// The default type's plaintext modulus (2^16).
    pub plaintext_modulus: u64,
    /// Every type a job can compute on (absent before HE Engine 0.5: `u16` only).
    #[serde(default)]
    pub integer_types: Vec<IntegerType>,
    pub operations: Vec<Operation>,
    pub max_ciphertext_bytes: u64,
    /// Most encrypted inputs one job takes (a `sum`).
    #[serde(default)]
    pub max_inputs: usize,
    /// Most input bytes one job takes, all inputs together.
    #[serde(default)]
    pub max_job_input_bytes: u64,
    /// Most jobs in one batch (`POST /api/v1/compute/jobs/batch`); a batch's
    /// inputs together are limited like one job's.
    #[serde(default)]
    pub max_batch_jobs: usize,
    /// Most steps in one program.
    #[serde(default)]
    pub max_program_steps: usize,
    pub max_server_key_bytes: u64,
    pub max_keys_per_user: i64,
    /// Absent on servers before HE Engine 0.5, which take no proven inputs.
    #[serde(default)]
    pub proofs: Option<ProofParams>,
}

/// How to send zero-knowledge-proven inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ProofParams {
    /// Lower-case hex SHA-256 of the CRS served at `GET /api/v1/he/crs`.
    pub crs_sha256: String,
    /// Most plaintext bits one proven list may hold.
    pub max_bits: usize,
    pub max_list_bytes: u64,
    pub max_public_key_bytes: u64,
    /// Proofs are made with metadata `<metadata_prefix><key id>`.
    #[cfg_attr(feature = "openapi", schema(example = "he-engine/proof/v1/"))]
    pub metadata_prefix: String,
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
    /// The key was made with the compact-public-key parameters, so it can take
    /// proven inputs once its public key is uploaded. Keys from before HE Engine
    /// 0.5 cannot.
    #[serde(default)]
    pub supports_proofs: bool,
    /// The matching compact public key has been uploaded
    /// (`PUT /api/v1/keys/{id}/public-key`).
    #[serde(default)]
    pub has_public_key: bool,
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

/// `POST /api/v1/compute/jobs`: compute `operation` on encrypted inputs.
///
/// The inputs are either `inputs` (one ciphertext each) or `proven_inputs` (one
/// zero-knowledge-proven list holding all of them), never both. Binary operations
/// take two inputs, or one input and a `scalar`; `sum` takes 2 to `max_inputs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct CreateJobRequest {
    /// One of the caller's registered server keys.
    pub key_id: String,
    pub operation: Operation,
    /// The inputs' type; `u16` if absent.
    #[serde(default)]
    pub integer_type: IntegerType,
    /// Standard base64 of `safe_serialize`d ciphertexts of `integer_type` (e.g.
    /// `FheUint16`), encrypted with the client key that belongs to `key_id`.
    #[serde(default)]
    pub inputs: Vec<String>,
    /// Standard base64 of one `safe_serialize`d `ProvenCompactCiphertextList`
    /// encrypted under the key's public key, proven against the server's CRS with
    /// metadata `he-engine/proof/v1/<key_id>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proven_inputs: Option<String>,
    /// A plaintext right-hand operand in decimal, e.g. `"-7"`. The server sees it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scalar: Option<String>,
    /// The steps to run, for `operation: "program"` (and only then).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<Program>,
}

/// `POST /api/v1/compute/jobs/batch`: several jobs, queued together or not at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct BatchJobsRequest {
    /// 1 to `max_batch_jobs` jobs, each as for `POST /api/v1/compute/jobs`.
    pub jobs: Vec<CreateJobRequest>,
}

/// The queued jobs of a batch, in request order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct BatchJobsResponse {
    pub jobs: Vec<JobSummary>,
}

/// A job as its owner sees it: metadata only, never ciphertexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct JobSummary {
    pub id: String,
    pub status: JobStatus,
    pub operation: Operation,
    // The defaults describe jobs from servers before HE Engine 0.5.
    #[serde(default)]
    pub integer_type: IntegerType,
    /// The type to decrypt the result as: `bool` for comparisons.
    #[serde(default = "default_result_type")]
    pub result_type: ValueType,
    /// Number of encrypted inputs.
    #[serde(default = "default_input_count")]
    pub input_count: i64,
    /// The inputs were a zero-knowledge-proven list.
    #[serde(default)]
    pub proven: bool,
    /// The plaintext right-hand operand, if the job has one.
    #[serde(default)]
    pub scalar: Option<String>,
    /// The program, for `operation: "program"`.
    #[serde(default)]
    #[cfg_attr(feature = "sqlx", sqlx(json(nullable)))]
    pub program: Option<Program>,
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

fn default_result_type() -> ValueType {
    ValueType::U16
}

fn default_input_count() -> i64 {
    2
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
            "id": "j", "status": "completed", "operation": "multiply",
            "integer_type": "u16", "result_type": "u16", "input_count": 2,
            "proven": false, "scalar": null, "program": null, "key_id": null,
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
    fn job_requests_from_older_clients_default_to_u16_ciphertexts() {
        let req: CreateJobRequest = serde_json::from_value(serde_json::json!({
            "key_id": "k", "operation": "add", "inputs": ["YQ==", "Yg=="]
        }))
        .unwrap();
        assert_eq!(req.integer_type, IntegerType::U16);
        assert!(req.proven_inputs.is_none() && req.scalar.is_none());
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("scalar").is_none() && json.get("proven_inputs").is_none());
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
