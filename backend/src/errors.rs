//! Errors and the API's error envelope.
//!
//! Every error response, whether from a handler, a middleware, a body or query
//! extractor or actix itself (unknown route, wrong method, oversized body), has
//! the body `{"error": {"code": "...", "message": "..."}}` (`heaas_core::api::ErrorBody`).

use actix_web::body::MessageBody;
use actix_web::dev::ServiceResponse;
use actix_web::error::{JsonPayloadError, PathError, QueryPayloadError};
use actix_web::http::{header, StatusCode};
use actix_web::middleware::{ErrorHandlerResponse, ErrorHandlers};
use actix_web::{HttpRequest, HttpResponse, ResponseError};
use heaas_core::api::{error_codes, ErrorBody, ErrorDetail};
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    BadRequest(String),
    Conflict(String),
    PayloadTooLarge(String),
    UnsupportedMediaType(String),
    /// The request is well formed but cannot be applied (e.g. a body of the
    /// wrong shape, or an `Idempotency-Key` reused for a different request).
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
    /// Details are logged, never returned.
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

    /// The envelope's machine-readable `code`.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::Unauthorized(_) => error_codes::UNAUTHORIZED,
            AppError::Forbidden(_) => error_codes::FORBIDDEN,
            AppError::NotFound(_) => error_codes::NOT_FOUND,
            AppError::BadRequest(_) => error_codes::BAD_REQUEST,
            AppError::Conflict(_) => error_codes::CONFLICT,
            AppError::PayloadTooLarge(_) => error_codes::PAYLOAD_TOO_LARGE,
            AppError::UnsupportedMediaType(_) => error_codes::UNSUPPORTED_MEDIA_TYPE,
            AppError::Unprocessable(_) => error_codes::UNPROCESSABLE,
            AppError::TooManyRequests { .. } => error_codes::RATE_LIMITED,
            AppError::ServiceUnavailable { .. } => error_codes::UNAVAILABLE,
            AppError::Internal(_) => error_codes::INTERNAL,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Unauthorized(m)
            | AppError::Forbidden(m)
            | AppError::NotFound(m)
            | AppError::BadRequest(m)
            | AppError::Conflict(m)
            | AppError::PayloadTooLarge(m)
            | AppError::UnsupportedMediaType(m)
            | AppError::Unprocessable(m) => f.write_str(m),
            AppError::TooManyRequests { message, .. }
            | AppError::ServiceUnavailable { message, .. } => f.write_str(message),
            AppError::Internal(_) => f.write_str("Internal server error"),
        }
    }
}

fn envelope(code: &str, message: String) -> ErrorBody {
    ErrorBody {
        error: ErrorDetail {
            code: code.to_string(),
            message,
        },
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
            AppError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::UnsupportedMediaType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            AppError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            AppError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        if let AppError::Internal(msg) = self {
            tracing::error!("Internal error: {}", msg);
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
        response.json(envelope(self.code(), self.to_string()))
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        if let sqlx::Error::Database(ref db_err) = err {
            if db_err.is_unique_violation() || db_err.message().contains("UNIQUE constraint") {
                return AppError::Conflict("That already exists".to_string());
            }
        }
        tracing::error!("Database error: {}", err);
        AppError::Internal("Database operation failed".to_string())
    }
}

// ── Extractor errors ─────────────────────────────────────────────────────────

/// `JsonConfig` error handler: syntax errors are 400, bodies of the wrong shape
/// 422, oversized bodies 413 and other content types 415.
pub fn json_error(err: JsonPayloadError, _req: &HttpRequest) -> actix_web::Error {
    let app = match &err {
        JsonPayloadError::Overflow { .. } | JsonPayloadError::OverflowKnownLength { .. } => {
            AppError::PayloadTooLarge("The request body is too large".into())
        }
        JsonPayloadError::ContentType => {
            AppError::UnsupportedMediaType("Send JSON with Content-Type: application/json".into())
        }
        JsonPayloadError::Deserialize(e) if e.is_data() => {
            AppError::Unprocessable(format!("Invalid request body: {e}"))
        }
        _ => AppError::BadRequest(format!("Malformed JSON: {err}")),
    };
    app.into()
}

pub fn query_error(err: QueryPayloadError, _req: &HttpRequest) -> actix_web::Error {
    AppError::bad_request(format!("Invalid query string: {err}")).into()
}

pub fn path_error(err: PathError, _req: &HttpRequest) -> actix_web::Error {
    AppError::not_found(format!("Not found: {err}")).into()
}

/// Rewrites any error response that is not JSON yet (actix's own 404/405/413
/// and the like) into the envelope; JSON errors pass through untouched.
pub fn envelope_errors<B: MessageBody + 'static>() -> ErrorHandlers<B> {
    ErrorHandlers::new().default_handler(|res: ServiceResponse<B>| {
        let is_json = res
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json"));
        if is_json {
            return Ok(ErrorHandlerResponse::Response(res.map_into_left_body()));
        }
        let status = res.status();
        let code = error_codes::for_status(status.as_u16());
        let message = match (status.is_server_error(), res.response().error()) {
            (false, Some(e)) => e.to_string(),
            _ => status.canonical_reason().unwrap_or("Error").to_string(),
        };
        let mut rewritten = HttpResponse::build(status);
        for (name, value) in res.headers() {
            if name != header::CONTENT_TYPE && name != header::CONTENT_LENGTH {
                rewritten.append_header((name.clone(), value.clone()));
            }
        }
        let rewritten = rewritten.json(envelope(code, message));
        let (req, _) = res.into_parts();
        Ok(ErrorHandlerResponse::Response(
            ServiceResponse::new(req, rewritten).map_into_right_body(),
        ))
    })
}
