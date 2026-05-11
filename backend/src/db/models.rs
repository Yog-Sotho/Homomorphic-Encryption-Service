use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Job {
    pub id: String,
    pub user_id: String,
    pub status: String,
    pub input_data_b64: String,
    pub operation: String,
    pub result_b64: Option<String>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    pub input_data_b64: String,
    pub operation: String,
}

#[derive(Debug, Serialize)]
pub struct JobResponse {
    pub id: String,
    pub status: String,
    pub result_b64: Option<String>,
    pub error_message: Option<String>,
}