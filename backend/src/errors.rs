use actix_web::{
    http::{header, StatusCode},
    HttpResponse, ResponseError,
};
use serde::Serialize;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    BadRequest(String),
    Conflict(String),
    /// The request is well formed but cannot be applied (e.g. an
    /// `Idempotency-Key` reused for a different request).
    Unprocessable(String),
    /// 429. `retry_after` (seconds) becomes a `Retry-After` header.
    TooManyRequests {
        message: String,
        retry_after: Option<u64>,
    },
    /// 503: temporarily unable to accept work; retry after `retry_after` seconds.
    ServiceUnavailable {
        message: String,
        retry_after: u64,
    },
    Internal(String),
}

impl AppError {
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        AppError::Unauthorized(msg.into())
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        AppError::Forbidden(msg.into())
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        AppError::NotFound(msg.into())
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        AppError::BadRequest(msg.into())
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        AppError::Conflict(msg.into())
    }
    pub fn unprocessable(msg: impl Into<String>) -> Self {
        AppError::Unprocessable(msg.into())
    }
    pub fn too_many_requests(msg: impl Into<String>, retry_after: Option<u64>) -> Self {
        AppError::TooManyRequests {
            message: msg.into(),
            retry_after,
        }
    }
    pub fn service_unavailable(msg: impl Into<String>, retry_after: u64) -> Self {
        AppError::ServiceUnavailable {
            message: msg.into(),
            retry_after,
        }
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
            AppError::Forbidden(m) => write!(f, "{}", m),
            AppError::NotFound(m) => write!(f, "{}", m),
            AppError::BadRequest(m) => write!(f, "{}", m),
            AppError::Conflict(m) => write!(f, "{}", m),
            AppError::Unprocessable(m) => write!(f, "{}", m),
            AppError::TooManyRequests { message, .. } => write!(f, "{}", message),
            AppError::ServiceUnavailable { message, .. } => write!(f, "{}", message),
            AppError::Internal(_) => write!(f, "Internal server error"),
        }
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            AppError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        if let AppError::Internal(msg) = self {
            log::error!("Internal error: {}", msg);
        }
        let mut response = HttpResponse::build(self.status_code());
        let retry_after = match self {
            AppError::TooManyRequests { retry_after, .. } => *retry_after,
            AppError::ServiceUnavailable { retry_after, .. } => Some(*retry_after),
            _ => None,
        };
        if let Some(seconds) = retry_after {
            response.insert_header((header::RETRY_AFTER, seconds.to_string()));
        }
        response.json(ErrorBody {
            message: self.to_string(),
        })
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        if let sqlx::Error::Database(ref db_err) = err {
            if db_err.is_unique_violation() || db_err.message().contains("UNIQUE constraint") {
                return AppError::BadRequest(
                    "An error occurred while processing the request".to_string(),
                );
            }
        }
        log::error!("Database error: {}", err);
        AppError::Internal("Database operation failed".to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        log::error!("JWT error: {}", err);
        AppError::Unauthorized("Invalid or expired token".to_string())
    }
}
