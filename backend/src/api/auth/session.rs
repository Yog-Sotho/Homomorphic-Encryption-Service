//! Sessions: a short-lived access token in the response body (kept in memory by
//! the client) and a long-lived refresh token in an `HttpOnly` cookie that page
//! scripts cannot read.
//!
//! Each sign-in starts a refresh-token *family*. A refresh marks the presented
//! token rotated and issues its successor in the same family. If a rotated token
//! is presented again after [`ROTATION_GRACE_SECS`], someone holds a copy of it,
//! so the whole family is revoked and both holders must sign in again.

use super::{hash_token, random_token, UserPublic, MAX_TOKEN_LEN};
use crate::config::Config;
use crate::errors::AppError;
use crate::middleware::jwt::issue_access_token;
use actix_web::cookie::{time, Cookie, SameSite};
use actix_web::{web, HttpRequest, HttpResponse, ResponseError};
use chrono::NaiveDateTime;
use serde::Deserialize;
use sqlx::{Sqlite, SqlitePool};
use std::sync::Arc;
use uuid::Uuid;

pub const REFRESH_COOKIE: &str = "heaas_refresh";
/// The refresh cookie is only ever sent to the auth endpoints.
pub const COOKIE_PATH: &str = "/api/v1/auth";
/// Two tabs refreshing at the same moment both present the same token; the
/// second within this window gets a session instead of revoking the family.
pub const ROTATION_GRACE_SECS: i64 = 10;
/// Rotated tokens are kept this long so a replay is recognised as one.
const ROTATED_RETENTION_DAYS: i64 = 7;
const LOGIN_CODE_TTL_SECS: i64 = 60;

pub use heaas_core::api::AuthResponse;

fn refresh_cookie(config: &Config, value: String, max_age: time::Duration) -> Cookie<'static> {
    Cookie::build(REFRESH_COOKIE, value)
        .path(COOKIE_PATH)
        .http_only(true)
        .secure(config.cookie_secure)
        .same_site(SameSite::Strict)
        .max_age(max_age)
        .finish()
}

/// Tells the browser to drop the refresh cookie.
pub fn clear_refresh_cookie(config: &Config) -> Cookie<'static> {
    refresh_cookie(config, String::new(), time::Duration::ZERO)
}

fn presented_token(req: &HttpRequest) -> Option<String> {
    req.cookie(REFRESH_COOKIE)
        .map(|c| c.value().to_string())
        .filter(|v| !v.is_empty() && v.len() <= MAX_TOKEN_LEN)
}

async fn user_public(pool: &SqlitePool, user_id: &str) -> Result<Option<UserPublic>, AppError> {
    Ok(
        sqlx::query_as("SELECT id, email, created_at FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await?,
    )
}

/// SQLite `datetime('now', ?)` modifier for when a refresh token expires.
fn session_expiry(config: &Config) -> String {
    format!("+{} days", config.ttl.session_days)
}

/// The response for any successful sign-in or refresh.
fn session_response(
    config: &Config,
    user: UserPublic,
    authenticated_at: NaiveDateTime,
    refresh_token: String,
) -> Result<HttpResponse, AppError> {
    let token = issue_access_token(&user.id, authenticated_at.and_utc().timestamp(), config)?;
    let cookie = refresh_cookie(
        config,
        refresh_token,
        time::Duration::days(config.ttl.session_days),
    );
    Ok(HttpResponse::Ok().cookie(cookie).json(AuthResponse {
        token,
        expires_in: config.ttl.access_token_secs,
        user,
    }))
}

/// Signs `user` in: starts a new refresh-token family authenticated now.
pub async fn start_session(
    pool: &SqlitePool,
    config: &Config,
    user: UserPublic,
) -> Result<HttpResponse, AppError> {
    let refresh = random_token();
    let id = Uuid::new_v4().to_string();
    let (authenticated_at,): (NaiveDateTime,) = sqlx::query_as(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, family_id, authenticated_at)
         VALUES (?, ?, ?, datetime('now', ?), ?, datetime('now'))
         RETURNING authenticated_at",
    )
    .bind(&id)
    .bind(&user.id)
    .bind(hash_token(&refresh))
    .bind(session_expiry(config))
    .bind(&id)
    .fetch_one(pool)
    .await?;
    session_response(config, user, authenticated_at, refresh)
}

/// Revokes every session of a user (password change, reset, account deletion).
pub async fn revoke_all<'e, E: sqlx::Executor<'e, Database = Sqlite>>(
    executor: E,
    user_id: &str,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// A 401 in the error envelope that also drops the refresh cookie.
fn signed_out(config: &Config, message: &str) -> HttpResponse {
    let mut response = AppError::unauthorized(message).error_response();
    if let Err(e) = response.add_cookie(&clear_refresh_cookie(config)) {
        log::error!("Could not clear the refresh cookie: {e}");
    }
    response
}

/// A rotated token presented again: within the grace window, or a replay.
#[derive(sqlx::FromRow)]
struct Rotated {
    id: String,
    user_id: String,
    family_id: String,
    within_grace: bool,
}

/// A token row claimed for rotation.
#[derive(sqlx::FromRow)]
struct Claimed {
    id: String,
    user_id: String,
}

/// `POST /api/v1/auth/refresh` — exchanges the refresh cookie for a new access
/// token and a new refresh cookie.
pub async fn refresh(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let pool = pool.get_ref();
    let Some(token) = presented_token(&req) else {
        return Ok(signed_out(&config, "Not signed in"));
    };
    let token_hash = hash_token(&token);

    // Atomically mark the token rotated, so two refreshes cannot both win.
    let claimed: Option<Claimed> = sqlx::query_as(
        "UPDATE refresh_tokens SET rotated_at = datetime('now')
         WHERE token_hash = ? AND rotated_at IS NULL AND expires_at > datetime('now')
         RETURNING id, user_id",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;

    let parent = match claimed {
        Some(claimed) => claimed,
        None => {
            // Not claimable: unknown, expired, or already rotated.
            let rotated: Option<Rotated> = sqlx::query_as(
                "SELECT id, user_id, family_id,
                        rotated_at > datetime('now', ?) AS within_grace
                 FROM refresh_tokens
                 WHERE token_hash = ? AND rotated_at IS NOT NULL AND expires_at > datetime('now')",
            )
            .bind(format!("-{ROTATION_GRACE_SECS} seconds"))
            .bind(&token_hash)
            .fetch_optional(pool)
            .await?;
            match rotated {
                Some(Rotated {
                    id,
                    user_id,
                    within_grace: true,
                    ..
                }) => Claimed { id, user_id },
                Some(Rotated {
                    user_id, family_id, ..
                }) => {
                    log::warn!(
                        "Rotated refresh token reused for user {user_id}; revoking its session"
                    );
                    sqlx::query("DELETE FROM refresh_tokens WHERE family_id = ?")
                        .bind(&family_id)
                        .execute(pool)
                        .await?;
                    return Ok(signed_out(
                        &config,
                        "Session revoked. Please sign in again.",
                    ));
                }
                None => {
                    return Ok(signed_out(
                        &config,
                        "Session expired. Please sign in again.",
                    ))
                }
            }
        }
    };

    let Some(user) = user_public(pool, &parent.user_id).await? else {
        return Ok(signed_out(&config, "Not signed in"));
    };
    let successor = random_token();
    let (authenticated_at,): (NaiveDateTime,) = sqlx::query_as(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, family_id, authenticated_at)
         SELECT ?, user_id, ?, datetime('now', ?), family_id, authenticated_at
         FROM refresh_tokens WHERE id = ?
         RETURNING authenticated_at",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(hash_token(&successor))
    .bind(session_expiry(&config))
    .bind(&parent.id)
    .fetch_one(pool)
    .await?;
    session_response(&config, user, authenticated_at, successor)
}

/// `POST /api/v1/auth/logout` — ends this browser's session (its whole family).
pub async fn logout(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    if let Some(token) = presented_token(&req) {
        sqlx::query(
            "DELETE FROM refresh_tokens WHERE family_id =
                 (SELECT family_id FROM refresh_tokens WHERE token_hash = ?)",
        )
        .bind(hash_token(&token))
        .execute(pool.get_ref())
        .await?;
    }
    Ok(HttpResponse::Ok()
        .cookie(clear_refresh_cookie(&config))
        .json(serde_json::json!({ "message": "Signed out" })))
}

/// Issues a one-time code that [`exchange`] turns into a session. OAuth callbacks
/// redirect to the frontend with it, so tokens never appear in a URL.
pub async fn create_login_code(pool: &SqlitePool, user_id: &str) -> Result<String, AppError> {
    let code = random_token();
    sqlx::query(
        "INSERT INTO login_codes (code_hash, user_id, expires_at)
         VALUES (?, ?, datetime('now', ?))",
    )
    .bind(hash_token(&code))
    .bind(user_id)
    .bind(format!("+{LOGIN_CODE_TTL_SECS} seconds"))
    .execute(pool)
    .await?;
    Ok(code)
}

#[derive(Deserialize)]
pub struct ExchangeRequest {
    pub code: String,
}

/// `POST /api/v1/auth/exchange` — redeems a one-time login code (once).
pub async fn exchange(
    pool: web::Data<SqlitePool>,
    config: web::Data<Arc<Config>>,
    body: web::Json<ExchangeRequest>,
) -> Result<HttpResponse, AppError> {
    let invalid = || AppError::unauthorized("Sign-in link expired. Please try again.");
    if body.code.is_empty() || body.code.len() > MAX_TOKEN_LEN {
        return Err(invalid());
    }
    let redeemed: Option<(String,)> = sqlx::query_as(
        "DELETE FROM login_codes WHERE code_hash = ? AND expires_at > datetime('now')
         RETURNING user_id",
    )
    .bind(hash_token(&body.code))
    .fetch_optional(pool.get_ref())
    .await?;
    let (user_id,) = redeemed.ok_or_else(invalid)?;
    let user = user_public(pool.get_ref(), &user_id)
        .await?
        .ok_or_else(invalid)?;
    start_session(pool.get_ref(), &config, user).await
}

/// Deletes expired refresh tokens and login codes, and rotated tokens old
/// enough that a replay no longer matters. Run periodically.
pub async fn purge_expired(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let tokens = sqlx::query(
        "DELETE FROM refresh_tokens
         WHERE expires_at <= datetime('now')
            OR (rotated_at IS NOT NULL AND rotated_at < datetime('now', ?))",
    )
    .bind(format!("-{ROTATED_RETENTION_DAYS} days"))
    .execute(pool)
    .await?
    .rows_affected();
    let codes = sqlx::query("DELETE FROM login_codes WHERE expires_at <= datetime('now')")
        .execute(pool)
        .await?
        .rows_affected();
    Ok(tokens + codes)
}

/// A bearer token for `user_id`, authenticated now (tests only).
#[cfg(test)]
pub fn make_jwt(user_id: &str, config: &Config) -> Result<String, AppError> {
    issue_access_token(user_id, chrono::Utc::now().timestamp(), config)
}
