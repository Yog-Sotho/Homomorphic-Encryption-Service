//! Email/password accounts: registration, sign-in, email verification and
//! password reset.
//!
//! Emailed links point at frontend pages (`/heaas/verify`, `/heaas/reset`) with
//! the token in the URL fragment, which browsers never send to a server. The
//! page then POSTs the token. GET requests never change state, so mail scanners
//! that prefetch links cannot consume them.
//!
//! Responses never reveal whether an address has an account.

use super::email::{Email, Mailer};
use super::session::{revoke_all, start_session};
use super::{app_url, hash_token, random_token, UserPublic, MAX_TOKEN_LEN};
use crate::api::validation::{is_strong_password, is_valid_email, PASSWORD_REQUIREMENTS};
use crate::config::Config;
use crate::errors::AppError;
use crate::middleware::rate_limit::RateLimits;
use actix_web::{web, HttpRequest, HttpResponse};
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Verified against when an account has no password, so every sign-in costs
/// one bcrypt verification and timing reveals nothing.
const DUMMY_HASH: &str = "$2b$12$WXQEq5YBFxVkx2j5bVBNNOLIGgWS0DVOvt0gp8b2ioY6O3S9XEi/6";
/// bcrypt only uses the first 72 bytes; longer inputs only cost CPU.
const MAX_PASSWORD_LEN: usize = 128;
const MAX_EMAIL_LEN: usize = 254;

const REGISTERED: &str =
    "Account created. Check your inbox to verify your email before signing in.";
const RESENT: &str =
    "If an unverified account exists for that email, a new verification link has been sent.";
const RESET_SENT: &str = "If an account with that email exists, a reset link has been sent.";

/// Hashes on a blocking thread (bcrypt is deliberately slow).
pub(crate) async fn hash_password(password: String) -> Result<String, AppError> {
    tokio::task::spawn_blocking(move || hash(password, DEFAULT_COST))
        .await
        .map_err(|e| AppError::internal(format!("Task join error: {e}")))?
        .map_err(|e| AppError::internal(e.to_string()))
}

/// Verifies on a blocking thread; an empty hash (no password) never matches.
pub(crate) async fn verify_password(password: String, hash: String) -> Result<bool, AppError> {
    let has_password = !hash.is_empty();
    let target = if has_password {
        hash
    } else {
        DUMMY_HASH.to_string()
    };
    let valid = tokio::task::spawn_blocking(move || verify(password, &target))
        .await
        .map_err(|e| AppError::internal(format!("Task join error: {e}")))?
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(valid && has_password)
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn message(text: &str) -> serde_json::Value {
    serde_json::json!({ "message": text })
}

/// SQLite `datetime('now', ?)` modifiers for when emailed links expire.
fn verify_link_expiry(config: &Config) -> String {
    format!("+{} hours", config.ttl.verify_link_hours)
}

fn reset_link_expiry(config: &Config) -> String {
    format!("+{} minutes", config.ttl.reset_link_minutes)
}

async fn send_verification(mailer: &Mailer, config: &Config, to: &str, token: &str) {
    let url = app_url(config, &format!("/verify#token={token}"));
    mailer
        .send(
            to,
            Email::Verify {
                url: &url,
                valid_hours: config.ttl.verify_link_hours,
            },
        )
        .await;
}

pub use heaas_core::api::Credentials;

/// `POST /api/v1/auth/register`
#[utoipa::path(post, path = "/auth/register", tag = "auth", request_body = heaas_core::api::Credentials, responses((status = 202, description = "Verification email sent. The same answer is given when the address already has an account.", body = heaas_core::api::MessageResponse), (status = 400, description = "Invalid email or weak password", body = heaas_core::api::ErrorBody), (status = 429, description = "Too many requests; see `Retry-After`", body = heaas_core::api::ErrorBody)))]
pub async fn register(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    mailer: web::Data<Mailer>,
    limits: web::Data<RateLimits>,
    http: HttpRequest,
    req: web::Json<Credentials>,
) -> Result<HttpResponse, AppError> {
    let req = req.into_inner();
    let email = normalize_email(&req.email);
    if !is_valid_email(&email) {
        return Err(AppError::bad_request(
            "Invalid email address. Provide a valid email (e.g. user@example.com).",
        ));
    }
    if !is_strong_password(&req.password) {
        return Err(AppError::bad_request(PASSWORD_REQUIREMENTS));
    }
    limits.check_email_request(&http)?;

    let password_hash = hash_password(req.password).await?;
    let token = random_token();
    let inserted = sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified, email_verify_token,
                            email_verify_expires_at)
         VALUES (?, ?, ?, 0, ?, datetime('now', ?))",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&email)
    .bind(&password_hash)
    .bind(hash_token(&token))
    .bind(verify_link_expiry(&config))
    .execute(pool.get_ref())
    .await;

    match inserted {
        Ok(_) => {
            if limits.may_email(&email) {
                send_verification(&mailer, &config, &email, &token).await;
            }
        }
        // The address is taken: answer exactly as for a new account.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {}
        Err(e) => return Err(e.into()),
    }
    Ok(HttpResponse::Accepted().json(message(REGISTERED)))
}

#[derive(sqlx::FromRow)]
struct LoginRow {
    id: String,
    email: String,
    created_at: chrono::NaiveDateTime,
    password_hash: String,
    email_verified: bool,
}

/// `POST /api/v1/auth/login`
#[utoipa::path(post, path = "/auth/login", tag = "auth", request_body = heaas_core::api::Credentials, responses((status = 200, description = "Signed in", body = heaas_core::api::AuthResponse, headers(("Set-Cookie" = String, description = "The `HttpOnly` refresh cookie (path `/api/v1/auth`)"))), (status = 401, description = "Wrong email or password, or the email is not verified", body = heaas_core::api::ErrorBody), (status = 429, description = "Too many requests; see `Retry-After`", body = heaas_core::api::ErrorBody)))]
pub async fn login(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    limits: web::Data<RateLimits>,
    req: web::Json<Credentials>,
) -> Result<HttpResponse, AppError> {
    let req = req.into_inner();
    let email = normalize_email(&req.email);
    let invalid = || AppError::unauthorized("Invalid credentials");
    if email.len() > MAX_EMAIL_LEN || req.password.len() > MAX_PASSWORD_LEN {
        return Err(invalid());
    }
    limits.check_login(&email)?;

    let row: Option<LoginRow> = sqlx::query_as(
        "SELECT id, email, created_at, password_hash, email_verified FROM users WHERE email = ?",
    )
    .bind(&email)
    .fetch_optional(pool.get_ref())
    .await?;
    // Always verify once, so unknown and known addresses take the same time.
    let hash = row
        .as_ref()
        .map(|r| r.password_hash.clone())
        .unwrap_or_default();
    let valid = verify_password(req.password, hash).await?;
    match row {
        Some(row) if valid && row.email_verified => {
            let user = UserPublic {
                id: row.id,
                email: row.email,
                created_at: row.created_at,
            };
            start_session(pool.get_ref(), &config, user).await
        }
        // Wrong password, unknown address, social-only or unverified account.
        _ => Err(invalid()),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct TokenRequest {
    pub token: String,
}

/// `POST /api/v1/auth/verify` — confirms the email address and signs the user in.
#[utoipa::path(post, path = "/auth/verify", tag = "auth", request_body = TokenRequest, responses((status = 200, description = "Email verified and signed in", body = heaas_core::api::AuthResponse, headers(("Set-Cookie" = String, description = "The `HttpOnly` refresh cookie (path `/api/v1/auth`)"))), (status = 400, description = "Invalid or expired verification link", body = heaas_core::api::ErrorBody)))]
pub async fn verify_email(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: web::Json<TokenRequest>,
) -> Result<HttpResponse, AppError> {
    let invalid = || AppError::bad_request("Invalid or expired verification link");
    if req.token.is_empty() || req.token.len() > MAX_TOKEN_LEN {
        return Err(invalid());
    }
    let user: Option<UserPublic> = sqlx::query_as(
        "UPDATE users
         SET email_verified = 1, email_verify_token = NULL, email_verify_expires_at = NULL
         WHERE email_verify_token = ? AND email_verified = 0
           AND email_verify_expires_at > datetime('now')
         RETURNING id, email, created_at",
    )
    .bind(hash_token(&req.token))
    .fetch_optional(pool.get_ref())
    .await?;
    start_session(pool.get_ref(), &config, user.ok_or_else(invalid)?).await
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LinkQuery {
    pub token: Option<String>,
}

/// Moves a token from a query string into the fragment of a frontend page.
fn to_page(config: &Config, page: &str, token: Option<&str>) -> HttpResponse {
    let fragment = token
        .filter(|t| !t.is_empty() && t.len() <= MAX_TOKEN_LEN)
        .map(|t| {
            let encoded: String = url::form_urlencoded::byte_serialize(t.as_bytes()).collect();
            format!("#token={encoded}")
        })
        .unwrap_or_default();
    HttpResponse::Found()
        .insert_header(("Location", app_url(config, &format!("{page}{fragment}"))))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .finish()
}

/// `GET /api/v1/auth/verify?token=` — links in emails sent before verification
/// moved to the frontend. Redirects without consuming the token.
#[utoipa::path(get, path = "/auth/verify", tag = "auth", params(LinkQuery), responses((status = 302, description = "Redirect to the frontend page, token in the fragment. Consumes nothing.")))]
pub async fn verify_link(
    config: web::Data<Arc<Config>>,
    query: web::Query<LinkQuery>,
) -> HttpResponse {
    to_page(&config, "/verify", query.token.as_deref())
}

/// `GET /api/v1/auth/forgot-password/redirect?token=` — the same for reset links.
#[utoipa::path(get, path = "/auth/forgot-password/redirect", tag = "auth", params(LinkQuery), responses((status = 302, description = "Redirect to the frontend page, token in the fragment. Consumes nothing.")))]
pub async fn reset_link(
    config: web::Data<Arc<Config>>,
    query: web::Query<LinkQuery>,
) -> HttpResponse {
    to_page(&config, "/reset", query.token.as_deref())
}

#[derive(Deserialize, ToSchema)]
pub struct EmailRequest {
    pub email: String,
}

/// `POST /api/v1/auth/resend-verification`
#[utoipa::path(post, path = "/auth/resend-verification", tag = "auth", request_body = EmailRequest, responses((status = 200, description = "Sent if an unverified account exists (the answer is the same either way)", body = heaas_core::api::MessageResponse), (status = 429, description = "Too many requests; see `Retry-After`", body = heaas_core::api::ErrorBody)))]
pub async fn resend_verification(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    mailer: web::Data<Mailer>,
    limits: web::Data<RateLimits>,
    http: HttpRequest,
    req: web::Json<EmailRequest>,
) -> Result<HttpResponse, AppError> {
    let email = normalize_email(&req.email);
    if !is_valid_email(&email) {
        return Ok(HttpResponse::Ok().json(message(RESENT)));
    }
    limits.check_email_request(&http)?;

    let token = random_token();
    let updated = sqlx::query(
        "UPDATE users SET email_verify_token = ?, email_verify_expires_at = datetime('now', ?)
         WHERE email = ? AND email_verified = 0",
    )
    .bind(hash_token(&token))
    .bind(verify_link_expiry(&config))
    .bind(&email)
    .execute(pool.get_ref())
    .await?;
    if updated.rows_affected() == 1 && limits.may_email(&email) {
        send_verification(&mailer, &config, &email, &token).await;
    }
    Ok(HttpResponse::Ok().json(message(RESENT)))
}

/// `POST /api/v1/auth/forgot-password`
#[utoipa::path(post, path = "/auth/forgot-password", tag = "auth", request_body = EmailRequest, responses((status = 200, description = "Sent if the account exists (the answer is the same either way)", body = heaas_core::api::MessageResponse), (status = 429, description = "Too many requests; see `Retry-After`", body = heaas_core::api::ErrorBody)))]
pub async fn forgot_password(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    mailer: web::Data<Mailer>,
    limits: web::Data<RateLimits>,
    http: HttpRequest,
    req: web::Json<EmailRequest>,
) -> Result<HttpResponse, AppError> {
    let email = normalize_email(&req.email);
    if !is_valid_email(&email) {
        return Ok(HttpResponse::Ok().json(message(RESET_SENT)));
    }
    limits.check_email_request(&http)?;

    let token = random_token();
    let updated = sqlx::query(
        "UPDATE users SET password_reset_token = ?, password_reset_expires_at = datetime('now', ?)
         WHERE email = ?",
    )
    .bind(hash_token(&token))
    .bind(reset_link_expiry(&config))
    .bind(&email)
    .execute(pool.get_ref())
    .await?;
    if updated.rows_affected() == 1 && limits.may_email(&email) {
        let url = app_url(&config, &format!("/reset#token={token}"));
        mailer
            .send(
                &email,
                Email::Reset {
                    url: &url,
                    valid_minutes: config.ttl.reset_link_minutes,
                },
            )
            .await;
    }
    Ok(HttpResponse::Ok().json(message(RESET_SENT)))
}

#[derive(Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

/// `POST /api/v1/auth/reset-password` — sets a new password (once per link) and
/// signs out every session.
#[utoipa::path(post, path = "/auth/reset-password", tag = "auth", request_body = ResetPasswordRequest, responses((status = 200, description = "Password set; every session is signed out", body = heaas_core::api::MessageResponse), (status = 400, description = "Invalid or expired link, or weak password", body = heaas_core::api::ErrorBody)))]
pub async fn reset_password(
    pool: web::Data<SqlitePool>,
    req: web::Json<ResetPasswordRequest>,
) -> Result<HttpResponse, AppError> {
    let req = req.into_inner();
    let invalid = || AppError::bad_request("Invalid or expired reset link");
    if req.token.is_empty() || req.token.len() > MAX_TOKEN_LEN {
        return Err(invalid());
    }
    if !is_strong_password(&req.new_password) {
        return Err(AppError::bad_request(PASSWORD_REQUIREMENTS));
    }
    let token_hash = hash_token(&req.token);
    const VALID: &str = "password_reset_token = ? AND password_reset_expires_at > datetime('now')";

    // Check before paying for bcrypt; the update below re-checks atomically.
    let exists: Option<(String,)> = sqlx::query_as(&format!("SELECT id FROM users WHERE {VALID}"))
        .bind(&token_hash)
        .fetch_optional(pool.get_ref())
        .await?;
    if exists.is_none() {
        return Err(invalid());
    }
    let password_hash = hash_password(req.new_password).await?;

    let mut tx = pool.begin().await?;
    // Following the link proves control of the mailbox, so the address is verified.
    let reset: Option<(String,)> = sqlx::query_as(&format!(
        "UPDATE users
         SET password_hash = ?, password_reset_token = NULL, password_reset_expires_at = NULL,
             email_verified = 1, email_verify_token = NULL, email_verify_expires_at = NULL
         WHERE {VALID}
         RETURNING id"
    ))
    .bind(&password_hash)
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let (user_id,) = reset.ok_or_else(invalid)?;
    revoke_all(&mut *tx, &user_id).await?;
    tx.commit().await?;

    Ok(HttpResponse::Ok().json(message("Password reset. You can now sign in.")))
}
