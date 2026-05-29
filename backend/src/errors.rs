use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Unauthorized(String),
    NotFound(String),
    BadRequest(String),
    Internal(String),
}

impl AppError {
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        AppError::Unauthorized(msg.into())
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        AppError::NotFound(msg.into())
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        AppError::BadRequest(msg.into())
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        AppError::Internal(msg.into())
    }
}

#[derive(Serialize)]
struct ErrorBody {
    message: String,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Unauthorized(m) => write!(f, "{}", m),
            AppError::NotFound(m) => write!(f, "{}", m),
            AppError::BadRequest(m) => write!(f, "{}", m),
            AppError::Internal(_) => write!(f, "Internal server error"),
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        if let AppError::Internal(msg) = self {
            log::error!("Internal error: {}", msg);
        }
        HttpResponse::build(self.status_code()).json(ErrorBody {
            message: self.to_string(),
        })
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        if let sqlx::Error::Database(ref db_err) = err {
            if db_err.is_unique_violation() || db_err.message().contains("UNIQUE constraint") {
                return AppError::BadRequest("Email address is already registered".to_string());
            }
        }
        log::error!("Database error: {}", err);
        AppError::Internal("Database operation failed".to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AppError::Unauthorized(format!("Auth error: {}", err))
    }
}
