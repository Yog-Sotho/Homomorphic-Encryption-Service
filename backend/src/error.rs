use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct AppError {
    pub message: String,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        let msg = self.message.to_lowercase();
        if msg.contains("invalid") || msg.contains("unsupported") {
            StatusCode::BAD_REQUEST
        } else if msg.contains("auth") || msg.contains("token") || msg.contains("credentials") {
            StatusCode::UNAUTHORIZED
        } else if msg.contains("not found") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(self)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        log::error!("Database error: {:?}", err);
        AppError { message: "Internal server error".into() }
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        log::error!("JWT error: {:?}", err);
        AppError { message: "Authentication error".into() }
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        log::error!("IO error: {:?}", err);
        AppError { message: "Internal server error".into() }
    }
}